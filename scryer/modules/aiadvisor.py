"""Optional local-LLM advisor — the reasoning layer on top of the rules brain.

When the operator wants a second opinion on the fuzzy calls ("which of these
creds is real?", "what's the actual foothold here?"), scryer can hand the recon
summary to a model running locally under Ollama and print its suggestion. This
is strictly optional and offline: no API key, no cost, no data leaves the box.
If Ollama isn't running, it prints a one-line hint and gets out of the way.

Enable with --ai (or SCRYER_AI=1). Model comes from --ai-model / $SCRYER_AI_MODEL,
default llama3.1. Endpoint from $SCRYER_OLLAMA (default http://localhost:11434).
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import List

from ..core import utils
from ..core.report import HostReport

_DEFAULT_ENDPOINT = "http://localhost:11434"
_DEFAULT_MODEL = "llama3.1"


def resolve(args):
    """Return (endpoint, model) for the local LLM, or None if unreachable."""
    endpoint = os.environ.get("SCRYER_OLLAMA", _DEFAULT_ENDPOINT).rstrip("/")
    model = (getattr(args, "ai_model", None) or os.environ.get("SCRYER_AI_MODEL")
             or _DEFAULT_MODEL)
    return (endpoint, model) if _reachable(endpoint) else None


def ask(args, prompt: str) -> str:
    """One-shot query to the resolved local model. '' on any failure."""
    got = resolve(args)
    return _generate(got[0], got[1], prompt) if got else ""


def advise(host: HostReport, args) -> None:
    if not (getattr(args, "ai", False) or os.environ.get("SCRYER_AI")):
        return
    endpoint = os.environ.get("SCRYER_OLLAMA", _DEFAULT_ENDPOINT).rstrip("/")
    model = (getattr(args, "ai_model", None) or os.environ.get("SCRYER_AI_MODEL")
             or _DEFAULT_MODEL)

    if not _reachable(endpoint):
        utils.log("dim", f"--ai: no Ollama at {endpoint} — start it "
                         "(`ollama serve` + `ollama pull llama3.1`) or set "
                         "$SCRYER_OLLAMA; skipping the AI advisor")
        return

    prompt = _build_prompt(host)
    utils.log("info", f"asking the local model ({model}) for the next move…")
    answer = _generate(endpoint, model, prompt)
    if not answer:
        utils.log("dim", "--ai: the local model returned nothing (is the model "
                         f"pulled? `ollama pull {model}`)")
        return

    print("\n" + utils.c("┌─[ AI ADVISOR  (local model: " + model + ") ]"
                        + "─" * 18, utils.C.MAGENTA, utils.C.BOLD))
    for line in answer.strip().splitlines():
        print("  " + line)
    print("  " + utils.c("(local-model suggestion — verify before you run it)",
                         utils.C.GREY))
    print()


# --------------------------------------------------------------------------
def _build_prompt(host: HostReport) -> str:
    from ..core import brain
    ports = ", ".join(
        f"{p['port']}/{p.get('service') or '?'}"
        for p in sorted(host.open_ports, key=lambda x: x["port"]))
    flags = [f.detail or f.title for f in host.findings if f.category == "flag"]
    notable: List[str] = []
    for f in sorted(host.findings, key=lambda x: x.rank()):
        if f.severity in ("critical", "high") and f.category != "flag":
            detail = (f.detail or "").replace("\n", " ")[:160]
            notable.append(f"- [{f.severity}] {f.title}: {detail}")
        if len(notable) >= 18:
            break
    moves = "\n".join(f"- {m.title}" for m in brain.build(host)[:6])
    creds = ", ".join(host.creds[:8]) or "none recovered yet"

    return (
        "You are an expert penetration tester assisting on an AUTHORISED "
        "CTF / lab machine. Based on the recon below, give the single most "
        "likely path to a foothold and then to the flag. Be concise and "
        "concrete: name the exact tools/commands for the next 2-3 steps. Do "
        "not hedge or add legal disclaimers.\n\n"
        f"Target: {host.target} ({host.resolved_ip})\n"
        f"OS guess: {host.os_guess or 'unknown'}\n"
        f"Web stack: {host.tech_stack or 'n/a'}\n"
        f"Open ports: {ports}\n"
        f"Recovered credentials: {creds}\n"
        f"Flags so far: {', '.join(flags) if flags else 'none'}\n\n"
        "Notable findings:\n" + ("\n".join(notable) or "- (little of note)") +
        "\n\nscryer's current ranked plan:\n" + (moves or "- (none)") +
        "\n\nWhat is the most promising next step, and exactly how?")


def _reachable(endpoint: str) -> bool:
    try:
        host, port = _split(endpoint)
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except (OSError, ValueError):
        return False


def _split(endpoint: str):
    hostport = endpoint.split("://", 1)[-1]
    host, _, port = hostport.partition(":")
    return host or "localhost", int(port or 11434)


def _generate(endpoint: str, model: str, prompt: str) -> str:
    payload = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(
        f"{endpoint}/api/generate", data=payload,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return data.get("response", "").strip()
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        utils.log("dim", f"--ai: Ollama request failed ({str(exc)[:60]})")
        return ""
