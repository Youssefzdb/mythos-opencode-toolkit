#!/usr/bin/env python3
"""
Mythos Security Review v2 — chunked, multi-pass, EXECUTION-VERIFIED
vulnerability-hunting workflow for source repos, on free OpenCode Zen models.

What makes real Claude Mythos effective isn't a secret model — it's the loop:
  read code -> hypothesize -> write a PoC -> RUN it -> observe -> refine.
v1 of this tool only did the first two steps (reasoning-only, two LLM passes).
v2 adds the missing piece: for the highest-severity confirmed findings, spin
up a live opencode agent session (bash + file-edit enabled) in a scratch
copy of the target file, have it actually WRITE and EXECUTE a minimal PoC,
and only keep findings that are empirically reproduced or explained why not.

Passes:
  1. Prioritize + chunk files (crypto/parsers/auth/memory-unsafe first).
  2. Hypothesis pass  (mimo-v2.5-free)       -> candidate findings, per chunk.
  3. Verification pass (deepseek-v4-flash-free) -> kill reasoning-only false positives.
  4. Execution pass   (mimo-v2.5-free + bash) -> for top N confirmed high/critical
     findings, actually compile/run a PoC and record real output.
  5. Exploit-chain pass -> if 2+ findings survive, ask the model whether they
     can be CHAINED into a single deeper attack path (mirrors Mythos's
     multi-bug chains, e.g. the 4-bug Firefox sandbox escape).
  6. Markdown report.

Usage:
  python3 mythos_security_review.py <path-to-code-dir> [--max-chunks N] [--max-exec M] [--out report.md]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mythos_common import MythosServer, extract_json, log, HYPOTHESIS_MODEL, VERIFY_MODEL, EXECUTOR_MODEL

PRIORITY_PATTERNS = [
    r"crypto", r"cipher", r"hash", r"auth", r"login", r"session",
    r"pars(e|ing)", r"decode", r"deserial", r"unmarshal", r"pickle",
    r"yaml", r"template", r"exec", r"eval", r"system\(", r"popen",
    r"strcpy", r"memcpy", r"sprintf", r"malloc", r"free\(", r"unsafe",
    r"ffi", r"syscall", r"sql", r"query", r"upload", r"path", r"file",
]
CODE_EXT = {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".rs", ".go", ".py",
            ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".cs"}
EXECUTABLE_EXT = {".c", ".cpp", ".cc", ".cxx", ".py", ".js"}  # languages we can try to actually run
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "target"}

CHUNK_LINES = 180
CHUNK_OVERLAP = 20
PORT_BASE = 4180


def collect_files(root):
    scored = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext not in CODE_EXT:
                continue
            full = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size == 0 or size > 400_000:
                continue
            score = sum(1 for pat in PRIORITY_PATTERNS if re.search(pat, full.lower()))
            scored.append((score, full))
    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored]


def chunk_file(path):
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []
    chunks = []
    if len(lines) <= CHUNK_LINES:
        chunks.append((1, len(lines), "".join(lines)))
    else:
        start = 0
        while start < len(lines):
            end = min(start + CHUNK_LINES, len(lines))
            chunks.append((start + 1, end, "".join(lines[start:end])))
            if end == len(lines):
                break
            start = end - CHUNK_OVERLAP
    return chunks


HYPOTHESIS_PROMPT = """You are reviewing a chunk of source code for exploitable security vulnerabilities \
(memory corruption, injection, auth bypass, deserialization, logic bugs, race conditions, etc). \
Be rigorous like a senior offensive-security researcher — only flag things with a concrete, plausible attack path.

File: {path}
Lines: {start}-{end}

```
{code}
```

Respond with ONLY a JSON array (no prose) of findings. Empty array [] if nothing credible. \
Each: {{"title": str, "cwe": str, "severity": "low|medium|high|critical", "confidence": "low|medium|high", \
"lines": str, "explanation": str, "attack_scenario": str}}"""

VERIFY_PROMPT = """You are an independent, skeptical second reviewer double-checking a vulnerability hypothesis. \
Kill false positives. Re-read the code carefully.

File: {path}  Lines: {start}-{end}
```
{code}
```
Hypothesis: {finding}

Respond with ONLY a JSON object: {{"verdict": "confirmed|false_positive|needs_more_context", "reasoning": str, \
"final_severity": "low|medium|high|critical"}}"""

EXECUTION_PROMPT = """You have bash and file-edit tools in this working directory. A copy of the vulnerable file \
is here: {filename}

Confirmed vulnerability hypothesis to EMPIRICALLY verify by actually running code (not just reasoning):
{finding}

Do this:
1. Write a minimal, self-contained PoC/harness that exercises the vulnerable code path (add a main()/entrypoint if \
needed for a library file; for Python/JS, write a small driver script; for C/C++, compile with gcc/g++).
2. Actually run it (compile first if needed) and observe the real output/crash/behavior.
3. Iterate at most 2 times if your first attempt doesn't compile/run cleanly.

When done, respond with ONLY a JSON object (no prose, no markdown fence) summarizing the empirical result: \
{{"executed": true|false, "reproduced": true|false, "observed_behavior": str, "poc_summary": str}}"""

CHAIN_PROMPT = """You are an exploit-chain analyst. Below are several INDEPENDENTLY CONFIRMED vulnerability findings \
from the same codebase. Determine whether any subset of them can be CHAINED into a single deeper attack path \
(e.g., an info-leak that defeats ASLR feeding into a memory-corruption bug, or an auth-bypass that unlocks an \
otherwise-unreachable injection sink). Only propose chains with a concrete, plausible mechanism — not just \
"both are bad so combine them".

Findings:
{findings}

Respond with ONLY a JSON array (no prose) of chain objects, or [] if no credible chain exists. \
Each: {{"chain_title": str, "steps": [str], "combined_severity": "high|critical", "rationale": str}}"""


def hypothesis_pass(server, session_id, chunks):
    findings = []
    for i, (path, start, end, code) in enumerate(chunks, 1):
        log(f"[{i}/{len(chunks)}] hypothesis: {path}:{start}-{end}", "mythos")
        prompt = HYPOTHESIS_PROMPT.format(path=path, start=start, end=end, code=code)
        resp = server.ask(session_id, HYPOTHESIS_MODEL, "mythos", prompt)
        parsed = extract_json(resp)
        if not parsed:
            continue
        for f in parsed:
            if isinstance(f, dict):
                f["_file"] = path
                f["_range"] = f"{start}-{end}"
                f["_code"] = code
                f["_abspath"] = path
                findings.append(f)
    return findings


def verify_pass(server, session_id, findings):
    verified = []
    for i, f in enumerate(findings, 1):
        log(f"[{i}/{len(findings)}] verify: {f.get('title')}", "mythos")
        s, e = f["_range"].split("-")
        vprompt = VERIFY_PROMPT.format(path=f["_file"], start=s, end=e, code=f["_code"],
                                        finding={k: v for k, v in f.items() if not k.startswith("_")})
        vresp = server.ask(session_id, VERIFY_MODEL, "mythos", vprompt)
        verdict = extract_json(vresp) or {"verdict": "needs_more_context", "reasoning": "verifier parse failed"}
        f["verdict"] = verdict.get("verdict", "needs_more_context")
        f["verify_reasoning"] = verdict.get("reasoning", "")
        f["final_severity"] = verdict.get("final_severity", f.get("severity", "unknown"))
        if f["verdict"] != "false_positive":
            verified.append(f)
    return verified


def execution_pass(verified, max_exec):
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    candidates = [f for f in verified if os.path.splitext(f["_abspath"])[1] in EXECUTABLE_EXT]
    candidates.sort(key=lambda f: sev_rank.get(f.get("final_severity", "unknown"), 4))
    to_execute = candidates[:max_exec]

    for i, f in enumerate(to_execute, 1):
        log(f"[{i}/{len(to_execute)}] execution-verify: {f.get('title')}", "mythos-exec")
        scratch = f"/tmp/mythos_exec_{int(time.time())}_{i}"
        os.makedirs(scratch, exist_ok=True)
        fname = os.path.basename(f["_abspath"])
        try:
            shutil.copy(f["_abspath"], os.path.join(scratch, fname))
        except Exception as e:
            f["execution_result"] = {"executed": False, "reproduced": False,
                                      "observed_behavior": f"could not stage file: {e}", "poc_summary": ""}
            continue

        port = PORT_BASE + i
        try:
            with MythosServer(port, cwd=scratch) as server:
                session_id = server.new_session()
                prompt = EXECUTION_PROMPT.format(
                    filename=fname,
                    finding=str({k: v for k, v in f.items() if not k.startswith("_")}),
                )
                resp = server.ask(session_id, EXECUTOR_MODEL, "mythos", prompt, timeout=180)
                result = extract_json(resp) or {"executed": False, "reproduced": False,
                                                 "observed_behavior": "could not parse executor response",
                                                 "poc_summary": resp[:500]}
                f["execution_result"] = result
        except Exception as e:
            f["execution_result"] = {"executed": False, "reproduced": False,
                                      "observed_behavior": f"executor error: {e}", "poc_summary": ""}
    return verified


def chain_pass(server, session_id, verified):
    if len(verified) < 2:
        return []
    summary = [{"title": f.get("title"), "file": f.get("_file", f.get("url", "web-target")),
                "severity": f.get("final_severity"),
                "explanation": f.get("explanation", f.get("attack_scenario", ""))} for f in verified]
    prompt = CHAIN_PROMPT.format(findings=str(summary))
    resp = server.ask(session_id, HYPOTHESIS_MODEL, "mythos", prompt)
    return extract_json(resp) or []


def run_review(target, max_chunks, max_exec, out_path):
    files = collect_files(target)
    if not files:
        log("no candidate source files found")
        return
    log(f"found {len(files)} candidate files, building chunks (priority order)...")

    all_chunks = []
    for f in files:
        for start, end, code in chunk_file(f):
            all_chunks.append((f, start, end, code))
    all_chunks = all_chunks[:max_chunks]
    log(f"scanning {len(all_chunks)} chunks (cap={max_chunks})")

    with MythosServer(PORT_BASE) as server:
        session_id = server.new_session()
        if not session_id:
            log("could not create opencode session — aborting")
            return

        findings = hypothesis_pass(server, session_id, all_chunks)
        log(f"hypothesis pass done: {len(findings)} raw candidates. running verification pass...")
        verified = verify_pass(server, session_id, findings)
        log(f"verification done: {len(verified)}/{len(findings)} survived. running chain analysis...")
        chains = chain_pass(server, session_id, verified)

    log(f"running execution-verification on top {max_exec} confirmed findings...")
    verified = execution_pass(verified, max_exec)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    verified.sort(key=lambda f: sev_rank.get(f.get("final_severity", "unknown"), 4))

    write_report(target, all_chunks, findings, verified, chains, out_path)
    log(f"done. {len(verified)}/{len(findings)} findings survived verification, {len(chains)} exploit chain(s). report: {out_path}")


def write_report(target, chunks, raw_findings, verified, chains, out_path):
    lines = [f"# Mythos Security Review — {os.path.basename(os.path.abspath(target))}", ""]
    lines.append(f"- Chunks scanned: {len(chunks)}")
    lines.append(f"- Raw hypotheses: {len(raw_findings)}")
    lines.append(f"- Confirmed / needs-context findings: {len(verified)}")
    lines.append(f"- Exploit chains identified: {len(chains)}")
    lines.append("")

    if chains:
        lines.append("## Exploit chains")
        for c in chains:
            lines.append(f"### {c.get('chain_title','(untitled chain)')} — {c.get('combined_severity','?').upper()}")
            for step in c.get("steps", []):
                lines.append(f"1. {step}")
            lines.append(f"\n{c.get('rationale','')}\n")

    lines.append("## Findings")
    if not verified:
        lines.append("No credible findings survived the verification pass.")
    for f in verified:
        lines.append(f"### [{f.get('final_severity','?').upper()}] {f.get('title','(untitled)')}")
        lines.append(f"- **File**: `{f['_file']}` lines {f['_range']}")
        lines.append(f"- **CWE**: {f.get('cwe','-')}  **Confidence**: {f.get('confidence','-')}")
        lines.append(f"- **Verifier verdict**: {f.get('verdict')} — {f.get('verify_reasoning','')}")
        er = f.get("execution_result")
        if er:
            mark = "✅ REPRODUCED" if er.get("reproduced") else ("⚠️ executed, not reproduced" if er.get("executed") else "— not executed")
            lines.append(f"- **Execution verification**: {mark}")
            lines.append(f"  - Observed: {er.get('observed_behavior','')}")
            if er.get("poc_summary"):
                lines.append(f"  - PoC: {er.get('poc_summary')}")
        lines.append("")
        lines.append(f"**Explanation**: {f.get('explanation','')}")
        lines.append("")
        lines.append(f"**Attack scenario**: {f.get('attack_scenario','')}")
        lines.append("")
        lines.append("```")
        lines.append(f["_code"].rstrip())
        lines.append("```")
        lines.append("")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="directory of source code to review")
    ap.add_argument("--max-chunks", type=int, default=40)
    ap.add_argument("--max-exec", type=int, default=3, help="max findings to empirically verify via real execution")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out_path = args.out or f"/app/mythos_report_{int(time.time())}.md"
    run_review(args.target, args.max_chunks, args.max_exec, out_path)
    print(out_path)


if __name__ == "__main__":
    main()
