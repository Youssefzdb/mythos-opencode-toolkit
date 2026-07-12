# Mythos OpenCode Toolkit

A from-scratch reproduction of Anthropic's **Mythos** methodology — the
hypothesis -> verify -> **execute** -> chain agentic loop — running on free
OpenCode Zen models instead of a frontier-scale model.

The thesis (also validated independently, e.g. by Vidoc Security's public
writeup reproducing Mythos-style findings with public models): most of
Mythos's edge comes from the **orchestration/scaffolding**, not a secret
model. This repo replicates that scaffolding.

## What's here

- `mythos_common.py` - shared plumbing: spins up a throwaway `opencode serve`
  instance per run, session/message helpers, robust JSON extraction from
  model output.
- `mythos_security_review.py` - repo/codebase scanner:
  1. **Prioritize + chunk** files (crypto/parsers/auth/memory-unsafe first).
  2. **Hypothesis pass** (`mimo-v2.5-free`) - candidate vulns per chunk.
  3. **Verification pass** (`deepseek-v4-flash-free`) - independent, skeptical
     second model kills reasoning-only false positives.
  4. **Execution pass** - for the top N confirmed high/critical findings, a
     live agent session (bash + file-edit tools) actually **writes and runs**
     a minimal PoC in a scratch copy of the file and records the real,
     empirical result (compiled/run, crash or not, actual output) - not just
     more reasoning.
  5. **Exploit-chain pass** - checks whether 2+ confirmed findings can be
     chained into one deeper attack path.
  6. Markdown report.
- `mythos_web_review.py` - same loop for **live web targets** instead of
  source: header/TLS audit, baselined sensitive-path probing (kills false
  positives on SPA catch-all routing), reflected-parameter signal detection,
  then the same hypothesis -> verify pass.
- `prompts/mythos.txt` - the system prompt used for the underlying OpenCode
  agent persona.

## Usage

\`\`\`bash
pip install -r requirements.txt
# needs the \`opencode\` CLI on PATH (https://opencode.ai)

python3 mythos_security_review.py /path/to/repo --max-chunks 40 --max-exec 3 --out report.md
python3 mythos_web_review.py https://your-authorized-target.example --out web_report.md
\`\`\`

## Scope / ethics

Only point these at code/targets you own or are explicitly authorized to
test. The web recon tool is read-only + non-destructive probes only (no
auth bruteforce, no destructive payloads). The repo scanner's execution
pass runs PoCs in an isolated scratch directory, not the original tree.
