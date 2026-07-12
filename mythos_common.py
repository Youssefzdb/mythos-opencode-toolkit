"""
Shared plumbing for the Mythos skills (repo scanner + web recon):
opencode server lifecycle, HTTP client helpers, JSON extraction, model list.

All Mythos skills import this instead of duplicating the boilerplate.
"""
import base64
import json
import os
import random
import string
import subprocess
import sys
import time
import urllib.request

OPENCODE_BIN = os.path.expanduser("~/.opencode/bin/opencode")
HOST = "127.0.0.1"

# Free OpenCode Zen models — no API key / login needed. We rotate between two
# distinct models for hypothesis vs verification so the second pass is a real
# independent check, not the same model grading its own homework.
HYPOTHESIS_MODEL = "mimo-v2.5-free"
VERIFY_MODEL = "deepseek-v4-flash-free"
EXECUTOR_MODEL = "mimo-v2.5-free"  # needs bash tool access, same agent config


def log(msg, prefix="mythos"):
    print(f"[{prefix}] {msg}", file=sys.stderr, flush=True)


class MythosServer:
    """Context-manager wrapping a throwaway opencode server instance."""

    def __init__(self, port, cwd=None):
        self.port = port
        self.cwd = cwd
        self.password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        self.base_url = f"http://{HOST}:{self.port}"
        self.proc = None

    def _basic_auth(self):
        return base64.b64encode(f"opencode:{self.password}".encode()).decode()

    def __enter__(self):
        env = os.environ.copy()
        env["OPENCODE_SERVER_PASSWORD"] = self.password
        self.proc = subprocess.Popen(
            [OPENCODE_BIN, "serve", "--hostname", HOST, "--port", str(self.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=self.cwd,
        )
        for _ in range(30):
            try:
                req = urllib.request.Request(f"{self.base_url}/doc")
                req.add_header("Authorization", "Basic " + self._basic_auth())
                urllib.request.urlopen(req, timeout=2)
                return self
            except Exception:
                time.sleep(0.5)
        self.proc.kill()
        raise RuntimeError("opencode server never became ready")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.kill()

    def _post(self, path, body, timeout=90):
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Basic " + self._basic_auth())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log(f"request failed on {path}: {e}")
            return None

    def new_session(self, directory=None):
        body = {}
        r = self._post("/session", body)
        return r["id"] if r else None

    def ask(self, session_id, model, agent, text, timeout=120):
        r = self._post(f"/session/{session_id}/message", {
            "model": {"providerID": "opencode", "modelID": model},
            "agent": agent,
            "parts": [{"type": "text", "text": text}],
        }, timeout=timeout)
        if not r:
            return ""
        return "\n".join(p["text"] for p in r.get("parts", []) if p.get("type") == "text")


def extract_json(text):
    import re
    m = re.search(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    blob = m.group(1) if m else text
    m2 = re.search(r"(\[.*\]|\{.*\})", blob, re.S)
    blob = m2.group(1) if m2 else blob
    try:
        return json.loads(blob)
    except Exception:
        return None
