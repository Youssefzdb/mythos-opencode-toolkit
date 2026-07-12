#!/usr/bin/env python3
"""
Mythos Loop — single-command, end-to-end, non-stop pentest orchestrator.

Ties the repo scanner (mythos_security_review) and live web recon
(mythos_web_review) into ONE continuous pipeline that runs start-to-finish
without manual restarts between phases, and adds a REFINEMENT LOOP on top of
the base hypothesis->verify pass so uncertain findings get a second, deeper
look before the run concludes — mirroring Mythos's persistent, long-horizon
iteration instead of a single reasoning pass.

Pipeline (fully automatic, no pauses):
  1. Collect + prioritize + chunk targets (repo dir and/or live URL).
  2. Hypothesis pass on everything.
  3. Verify pass (independent second model).
  4. REFINEMENT ROUNDS (up to --max-rounds): anything verdict=needs_more_context
     or needs_active_testing gets re-hypothesized with the prior verifier
     reasoning as extra context, then re-verified. Repeats until nothing
     changes state or --max-rounds is hit.
  5. Execution-verification pass (repo mode only): top N confirmed
     high/critical findings get an actual PoC written and RUN.
  6. Exploit-chain pass across the final combined finding set.
  7. One unified Markdown report covering repo + web.

Usage:
  python3 mythos_loop.py --repo /path/to/code --web https://target.example \
      --max-rounds 2 --max-exec 3 --max-chunks 40 --out full_pentest_report.md

  At least one of --repo / --web is required. Both can be given together for
  one combined run (e.g. reviewing an app's source AND its live deployment).
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mythos_security_review as repo_mod
import mythos_web_review as web_mod
from mythos_common import MythosServer, extract_json, log, HYPOTHESIS_MODEL, VERIFY_MODEL

UNCERTAIN_VERDICTS = {"needs_more_context", "needs_active_testing"}

REFINE_PROMPT = """You already investigated this finding once and the verifier flagged it as uncertain \
rather than confirmed or false. Take a SECOND, DEEPER look — this is round {round_num} of refinement, so \
be decisive this time; only stay uncertain if truly impossible to resolve from the given evidence.

Original finding:
{finding}

Verifier's prior reasoning (why it stayed uncertain):
{prior_reasoning}

Extra context / code:
{context}

Respond with ONLY a JSON object: {{"verdict": "confirmed|false_positive|needs_more_context", \
"reasoning": str, "final_severity": "low|medium|high|critical"}}"""


def refine_round(server, session_id, findings, round_num):
    """Re-examine uncertain findings with extra context. Mutates findings in place."""
    uncertain = [f for f in findings if f.get("verdict") in UNCERTAIN_VERDICTS]
    if not uncertain:
        return 0
    changed = 0
    for i, f in enumerate(uncertain, 1):
        log(f"[{i}/{len(uncertain)}] refine round {round_num}: {f.get('title')}", "mythos-loop")
        context = f.get("_code", "") or f.get("evidence", "")
        prompt = REFINE_PROMPT.format(
            round_num=round_num,
            finding={k: v for k, v in f.items() if not k.startswith("_")},
            prior_reasoning=f.get("verify_reasoning", ""),
            context=str(context)[:3000],
        )
        resp = server.ask(session_id, VERIFY_MODEL, "mythos", prompt, timeout=90)
        verdict = extract_json(resp)
        if not verdict:
            continue
        old_verdict = f.get("verdict")
        f["verdict"] = verdict.get("verdict", old_verdict)
        f["verify_reasoning"] = verdict.get("reasoning", f.get("verify_reasoning", ""))
        f["final_severity"] = verdict.get("final_severity", f.get("final_severity"))
        if f["verdict"] != old_verdict:
            changed += 1
    return changed


def run_loop(repo_target, web_target, max_rounds, max_exec, max_chunks, out_path):
    t0 = time.time()
    repo_findings, repo_verified, chunks = [], [], []
    web_findings, web_verified = [], []
    web_evidence = {}

    with MythosServer(4199) as server:
        session_id = server.new_session()
        if not session_id:
            log("could not create opencode session — aborting", "mythos-loop")
            return

        # ---- Phase 1: repo ----
        if repo_target:
            log(f"=== PHASE: repo scan — {repo_target} ===", "mythos-loop")
            files = repo_mod.collect_files(repo_target)
            for f in files:
                for start, end, code in repo_mod.chunk_file(f):
                    chunks.append((f, start, end, code))
            chunks = chunks[:max_chunks]
            log(f"{len(files)} candidate files -> {len(chunks)} chunks", "mythos-loop")
            repo_findings = repo_mod.hypothesis_pass(server, session_id, chunks)
            repo_verified = repo_mod.verify_pass(server, session_id, repo_findings)
            log(f"repo: {len(repo_verified)}/{len(repo_findings)} survived initial verify", "mythos-loop")

        # ---- Phase 2: web ----
        if web_target:
            log(f"=== PHASE: web recon — {web_target} ===", "mythos-loop")
            target = web_target if web_target.startswith("http") else "https://" + web_target
            from urllib.parse import urljoin, urlparse
            import re as _re
            r = web_mod.safe_get(target)
            if r is None:
                log("web target unreachable, skipping web phase", "mythos-loop")
            else:
                headers_info = web_mod.audit_headers(r)
                parsed = urlparse(target)
                tls_info = web_mod.get_tls_info(parsed.hostname) if parsed.scheme == "https" else {"note": "http"}
                sensitive = web_mod.probe_sensitive_paths(target)
                links = web_mod.discover_links(target, r.text)
                robots = web_mod.safe_get(urljoin(target, "/robots.txt"))
                if robots and robots.status_code == 200:
                    for line in robots.text.splitlines():
                        m = _re.match(r"(?i)disallow:\s*(\S+)", line)
                        if m:
                            links.add(urljoin(target, m.group(1)))
                reflected = web_mod.probe_reflected_params(links)
                web_evidence = {"headers": headers_info, "sensitive": sensitive, "tls": tls_info,
                                 "reflected": reflected, "endpoints": list(links)[:30]}
                import json as _json
                prompt = web_mod.HYPOTHESIS_PROMPT.format(
                    target=target,
                    headers=_json.dumps(headers_info, indent=2),
                    sensitive=_json.dumps(sensitive, indent=2)[:4000],
                    tls=_json.dumps(tls_info, indent=2, default=str),
                    reflected=_json.dumps(reflected, indent=2),
                    endpoints="\n".join(list(links)[:30]),
                )
                resp = server.ask(session_id, HYPOTHESIS_MODEL, "mythos", prompt)
                web_findings = extract_json(resp) or []
                evidence_blob = _json.dumps(web_evidence, indent=2, default=str)
                for f in web_findings:
                    if not isinstance(f, dict):
                        continue
                    vprompt = web_mod.VERIFY_PROMPT.format(finding=_json.dumps(f), evidence=evidence_blob[:4000])
                    vresp = server.ask(session_id, VERIFY_MODEL, "mythos", vprompt)
                    verdict = extract_json(vresp) or {"verdict": "needs_active_testing", "reasoning": "parse failed"}
                    f["verdict"] = verdict.get("verdict", "needs_active_testing")
                    f["verify_reasoning"] = verdict.get("reasoning", "")
                    f["final_severity"] = verdict.get("final_severity", f.get("severity", "unknown"))
                    f["evidence"] = f.get("evidence", "")
                    if f["verdict"] != "false_positive":
                        web_verified.append(f)
                log(f"web: {len(web_verified)}/{len(web_findings)} survived initial verify", "mythos-loop")

        # ---- Phase 3: refinement loop (non-stop until converged or max-rounds) ----
        all_verified = repo_verified + web_verified
        for round_num in range(1, max_rounds + 1):
            uncertain_count = sum(1 for f in all_verified if f.get("verdict") in UNCERTAIN_VERDICTS)
            if uncertain_count == 0:
                log(f"no uncertain findings left — refinement converged after {round_num - 1} round(s)", "mythos-loop")
                break
            log(f"=== PHASE: refinement round {round_num}/{max_rounds} ({uncertain_count} uncertain) ===", "mythos-loop")
            changed = refine_round(server, session_id, all_verified, round_num)
            log(f"round {round_num}: {changed} verdict(s) changed", "mythos-loop")
            if changed == 0:
                log("no change this round — stopping refinement early", "mythos-loop")
                break

        # drop anything that flipped to false_positive during refinement
        all_verified = [f for f in all_verified if f.get("verdict") != "false_positive"]
        repo_verified = [f for f in all_verified if "_abspath" in f]
        web_verified = [f for f in all_verified if "_abspath" not in f]

        # ---- Phase 4: chain analysis across the FULL combined set ----
        log("=== PHASE: exploit-chain analysis (combined repo+web) ===", "mythos-loop")
        chains = repo_mod.chain_pass(server, session_id, all_verified) if len(all_verified) >= 2 else []

    # ---- Phase 5: execution-verification (repo findings only, needs bash/gcc access) ----
    if repo_verified:
        log(f"=== PHASE: execution-verification (top {max_exec}) ===", "mythos-loop")
        repo_verified = repo_mod.execution_pass(repo_verified, max_exec)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    repo_verified.sort(key=lambda f: sev_rank.get(f.get("final_severity", "unknown"), 4))
    web_verified.sort(key=lambda f: sev_rank.get(f.get("final_severity", "unknown"), 4))

    write_unified_report(repo_target, web_target, repo_findings, repo_verified,
                          web_findings, web_verified, chains, time.time() - t0, out_path)
    total_raw = len(repo_findings) + len(web_findings)
    total_verified = len(repo_verified) + len(web_verified)
    log(f"DONE in {time.time()-t0:.0f}s. {total_verified}/{total_raw} findings survived, "
        f"{len(chains)} exploit chain(s). report: {out_path}", "mythos-loop")


def write_unified_report(repo_target, web_target, repo_findings, repo_verified,
                          web_findings, web_verified, chains, elapsed, out_path):
    lines = ["# Mythos Loop — Full Pentest Report", ""]
    lines.append(f"- Repo target: `{repo_target or '-'}`")
    lines.append(f"- Web target: `{web_target or '-'}`")
    lines.append(f"- Runtime: {elapsed:.0f}s")
    lines.append(f"- Repo findings: {len(repo_verified)}/{len(repo_findings)} confirmed/uncertain-kept")
    lines.append(f"- Web findings: {len(web_verified)}/{len(web_findings)} confirmed/uncertain-kept")
    lines.append(f"- Exploit chains: {len(chains)}")
    lines.append("")

    if chains:
        lines.append("## Exploit chains")
        for c in chains:
            lines.append(f"### {c.get('chain_title','(untitled)')} — {c.get('combined_severity','?').upper()}")
            for step in c.get("steps", []):
                lines.append(f"1. {step}")
            lines.append(f"\n{c.get('rationale','')}\n")

    if repo_verified:
        lines.append("## Repo findings")
        for f in repo_verified:
            lines.append(f"### [{f.get('final_severity','?').upper()}] {f.get('title','(untitled)')}")
            lines.append(f"- **File**: `{f.get('_file','?')}` lines {f.get('_range','?')}")
            lines.append(f"- **Verdict**: {f.get('verdict')} — {f.get('verify_reasoning','')}")
            er = f.get("execution_result")
            if er:
                mark = "REPRODUCED (executed)" if er.get("reproduced") else ("executed, not reproduced" if er.get("executed") else "not executed")
                lines.append(f"- **Execution verification**: {mark} — {er.get('observed_behavior','')}")
            lines.append(f"- **Attack scenario**: {f.get('attack_scenario','')}")
            lines.append("")

    if web_verified:
        lines.append("## Web findings")
        for f in web_verified:
            lines.append(f"### [{f.get('final_severity','?').upper()}] {f.get('title','(untitled)')}")
            lines.append(f"- **Verdict**: {f.get('verdict')} — {f.get('verify_reasoning','')}")
            lines.append(f"- **Evidence**: {f.get('evidence','')}")
            lines.append(f"- **Attack scenario**: {f.get('attack_scenario','')}")
            lines.append(f"- **Next step**: {f.get('recommended_next_step','')}")
            lines.append("")

    if not repo_verified and not web_verified:
        lines.append("No credible findings survived the full loop.")

    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=None, help="path to source code directory")
    ap.add_argument("--web", default=None, help="URL of authorized live target")
    ap.add_argument("--max-rounds", type=int, default=2, help="max refinement rounds for uncertain findings")
    ap.add_argument("--max-exec", type=int, default=3, help="max findings to empirically verify via real execution")
    ap.add_argument("--max-chunks", type=int, default=40)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    if not args.repo and not args.web:
        print("error: need at least one of --repo or --web", file=sys.stderr)
        sys.exit(1)
    out_path = args.out or f"/app/mythos_full_report_{int(time.time())}.md"
    run_loop(args.repo, args.web, args.max_rounds, args.max_exec, args.max_chunks, out_path)
    print(out_path)


if __name__ == "__main__":
    main()
