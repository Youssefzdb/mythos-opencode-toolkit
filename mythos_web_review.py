#!/usr/bin/env python3
"""
Mythos Web Recon & Vulnerability Hypothesis — Mythos-style workflow for
LIVE websites/web apps instead of source repos.

IMPORTANT / SCOPE: only ever point this at a target you own or are
explicitly authorized to test. It performs read-only recon + gentle,
non-destructive probes (no exploitation, no auth bruteforce, no
destructive payloads). It ends with an LLM (free OpenCode Zen model)
reasoning over the evidence like a senior pentester, cross-checked by
a second model pass — same hypothesis->verify loop as the repo scanner.

Usage:
  python3 mythos_web_review.py https://target.example --out report.md
"""
import argparse
import json
import os
import re
import ssl
import socket
import sys
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mythos_common import MythosServer, extract_json, log, HYPOTHESIS_MODEL, VERIFY_MODEL

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
    "/wp-admin/", "/wp-login.php", "/admin/", "/administrator/", "/.well-known/security.txt",
    "/backup.zip", "/backup.sql", "/db.sql", "/config.php.bak", "/.DS_Store",
    "/server-status", "/phpinfo.php", "/.htaccess", "/.svn/entries",
    "/api/", "/api/docs", "/swagger.json", "/swagger-ui.html", "/graphql",
    "/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration",
    "/actuator/health", "/actuator/env", "/debug", "/.aws/credentials",
]
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]
MARKER = "mythosProbe" + "".join(random.choices(string.digits, k=6))

session = requests.Session()
session.headers.update({"User-Agent": "MythosWebRecon/1.0 (+authorized-security-testing)"})


def safe_get(url, timeout=10):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, verify=True)
    except Exception:
        return None


def get_tls_info(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "notAfter": cert.get("notAfter"),
                    "subject": cert.get("subject"),
                }
    except Exception as e:
        return {"error": str(e)}


def audit_headers(resp):
    present, missing = {}, []
    for h in SECURITY_HEADERS:
        if h in resp.headers:
            present[h] = resp.headers[h]
        else:
            missing.append(h)
    return {"present": present, "missing": missing,
            "server": resp.headers.get("Server", ""),
            "powered_by": resp.headers.get("X-Powered-By", "")}


def probe_sensitive_paths(base):
    # Baseline against a random nonexistent path — kills false positives on
    # SPAs / servers that catch-all everything to a 200 index page.
    junk = "/__mythos_baseline_" + "".join(random.choices(string.ascii_lowercase, k=12))
    baseline = safe_get(urljoin(base, junk))
    baseline_len = len(baseline.content) if baseline is not None else -1
    baseline_status = baseline.status_code if baseline is not None else -1

    findings = []
    for path in SENSITIVE_PATHS:
        r = safe_get(urljoin(base, path))
        if r is None or r.status_code != 200 or len(r.content) == 0:
            continue
        if r.status_code == baseline_status and len(r.content) == baseline_len:
            continue
        findings.append({"path": path, "status": r.status_code, "len": len(r.content),
                          "snippet": r.text[:200]})
    return findings


def discover_links(base, html):
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "form"]):
            src = tag.get("href") or tag.get("src") or tag.get("action")
            if not src:
                continue
            full = urljoin(base, src)
            if urlparse(full).netloc == urlparse(base).netloc:
                links.add(full)
    except Exception:
        pass
    return links


def probe_reflected_params(urls):
    findings = []
    for url in list(urls)[:15]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            continue
        for param in list(qs.keys())[:3]:
            test_qs = {k: (v[0] if k != param else MARKER) for k, v in qs.items()}
            test_url = parsed._replace(query=urlencode(test_qs)).geturl()
            r = safe_get(test_url)
            if r and MARKER in r.text:
                escaped = f"&lt;{MARKER}" in r.text or f"\\u003c{MARKER}" in r.text
                findings.append({
                    "url": test_url, "param": param, "reflected_raw": not escaped,
                    "note": "marker string reflected unescaped in response body" if not escaped else "reflected but appears escaped",
                })
    return findings


HYPOTHESIS_PROMPT = """You are a senior offensive-security researcher analyzing RECON DATA (not source code) \
collected from an authorized web app pentest target. Reason like Mythos: find concrete, plausible \
attack paths from the evidence, don't just restate the data.

TARGET: {target}

=== Security headers ===
{headers}

=== Sensitive path probe results (files/paths that returned HTTP 200 and differ from baseline) ===
{sensitive}

=== TLS info ===
{tls}

=== Reflected parameter probe (marker string echoed back) ===
{reflected}

=== Discovered same-origin endpoints (sample) ===
{endpoints}

Respond with ONLY a JSON array (no prose) of findings, prioritized by real-world exploitability. \
Each: {{"title": str, "category": "misconfig|injection|info-disclosure|auth|transport|other", \
"severity": "low|medium|high|critical", "confidence": "low|medium|high", "evidence": str, \
"attack_scenario": str, "recommended_next_step": str}}. Empty array [] if nothing credible."""

VERIFY_PROMPT = """Skeptical independent reviewer double-checking a web-app vulnerability hypothesis \
based on recon evidence only (no active exploitation was performed). Kill anything speculative or \
already mitigated by other evidence.

Hypothesis:
{finding}

Full evidence available:
{evidence}

Respond with ONLY a JSON object: {{"verdict": "confirmed|false_positive|needs_active_testing", \
"reasoning": str, "final_severity": "low|medium|high|critical"}}"""


def run_web_review(target, out_path):
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urlparse(target)
    log(f"recon: {target}")

    r = safe_get(target)
    if r is None:
        log("target unreachable — aborting")
        return
    headers_info = audit_headers(r)
    tls_info = get_tls_info(parsed.hostname) if parsed.scheme == "https" else {"note": "http, no TLS"}
    sensitive = probe_sensitive_paths(target)
    links = discover_links(target, r.text)

    robots = safe_get(urljoin(target, "/robots.txt"))
    if robots and robots.status_code == 200:
        for line in robots.text.splitlines():
            m = re.match(r"(?i)disallow:\s*(\S+)", line)
            if m:
                links.add(urljoin(target, m.group(1)))

    reflected = probe_reflected_params(links)

    log(f"discovered {len(links)} same-origin endpoints, {len(sensitive)} exposed sensitive paths, "
        f"{len(reflected)} reflected-param signals")

    evidence_blob = json.dumps({
        "headers": headers_info, "sensitive": sensitive, "tls": tls_info,
        "reflected": reflected, "endpoints": list(links)[:30],
    }, indent=2, default=str)

    with MythosServer(4178) as server:
        llm_session = server.new_session()
        prompt = HYPOTHESIS_PROMPT.format(
            target=target,
            headers=json.dumps(headers_info, indent=2),
            sensitive=json.dumps(sensitive, indent=2)[:4000],
            tls=json.dumps(tls_info, indent=2, default=str),
            reflected=json.dumps(reflected, indent=2),
            endpoints="\n".join(list(links)[:30]),
        )
        log("hypothesis pass...")
        resp = server.ask(llm_session, HYPOTHESIS_MODEL, "mythos", prompt)
        findings = extract_json(resp) or []

        verified = []
        for i, f in enumerate(findings, 1):
            if not isinstance(f, dict):
                continue
            log(f"[{i}/{len(findings)}] verify: {f.get('title')}")
            vprompt = VERIFY_PROMPT.format(finding=json.dumps(f), evidence=evidence_blob[:4000])
            vresp = server.ask(llm_session, VERIFY_MODEL, "mythos", vprompt)
            verdict = extract_json(vresp) or {"verdict": "needs_active_testing", "reasoning": "parse failed"}
            f["verdict"] = verdict.get("verdict", "needs_active_testing")
            f["verify_reasoning"] = verdict.get("reasoning", "")
            f["final_severity"] = verdict.get("final_severity", f.get("severity", "unknown"))
            if f["verdict"] != "false_positive":
                verified.append(f)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    verified.sort(key=lambda f: sev_rank.get(f.get("final_severity", "unknown"), 4))

    write_report(target, headers_info, tls_info, sensitive, reflected, links, findings, verified, out_path)
    log(f"done. {len(verified)}/{len(findings)} findings survived. report: {out_path}")


def write_report(target, headers_info, tls_info, sensitive, reflected, links, raw_findings, verified, out_path):
    lines = [f"# Mythos Web Recon — {target}", ""]
    lines.append(f"- Same-origin endpoints discovered: {len(links)}")
    lines.append(f"- Exposed sensitive paths (HTTP 200): {len(sensitive)}")
    lines.append(f"- Reflected-parameter signals: {len(reflected)}")
    lines.append(f"- Raw hypotheses: {len(raw_findings)} -> confirmed/needs-testing: {len(verified)}")
    lines.append("")
    lines.append("## Security headers")
    lines.append(f"- Present: {list(headers_info['present'].keys())}")
    lines.append(f"- Missing: {headers_info['missing']}")
    lines.append(f"- Server: `{headers_info['server']}`  X-Powered-By: `{headers_info['powered_by']}`")
    lines.append("")
    if sensitive:
        lines.append("## Exposed sensitive paths")
        for s in sensitive:
            lines.append(f"- `{s['path']}` -> HTTP {s['status']} ({s['len']} bytes)")
        lines.append("")
    if reflected:
        lines.append("## Reflected parameter signals")
        for rf in reflected:
            lines.append(f"- `{rf['url']}` param=`{rf['param']}` — {rf['note']}")
        lines.append("")
    lines.append("## Findings")
    if not verified:
        lines.append("No credible findings survived verification (recon-only pass; consider an authorized active-testing round).")
    for f in verified:
        lines.append(f"### [{f.get('final_severity','?').upper()}] {f.get('title','(untitled)')}")
        lines.append(f"- **Category**: {f.get('category','-')}  **Confidence**: {f.get('confidence','-')}")
        lines.append(f"- **Verdict**: {f.get('verdict')} — {f.get('verify_reasoning','')}")
        lines.append(f"- **Evidence**: {f.get('evidence','')}")
        lines.append(f"- **Attack scenario**: {f.get('attack_scenario','')}")
        lines.append(f"- **Next step**: {f.get('recommended_next_step','')}")
        lines.append("")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="URL of the site to review (must be authorized)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out_path = args.out or f"/app/mythos_web_report_{int(time.time())}.md"
    run_web_review(args.target, out_path)
    print(out_path)


if __name__ == "__main__":
    main()
