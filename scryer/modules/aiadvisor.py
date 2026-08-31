"""LLM reasoning layer — advisor + agent brain, local or via an API key.

scryer can hand the recon state to a model and get the next exploitation move.
Two backends:

  * Ollama (local, default): no API key, no cost, nothing leaves the box.
  * Any OpenAI-compatible chat API (DeepSeek, OpenAI, OpenRouter, Groq, a
    self-hosted endpoint): set an API key and scryer POSTs to /chat/completions.

Selection is automatic from the environment, or forced with --ai-provider:

    DeepSeek : export DEEPSEEK_API_KEY=...              (model deepseek-chat)
    OpenAI   : export OPENAI_API_KEY=...                (model gpt-4o-mini)
    Custom   : export SCRYER_AI_URL=https://host/v1/chat/completions \\
               SCRYER_AI_KEY=... SCRYER_AI_MODEL=...
    Ollama   : (nothing) — falls back to http://localhost:11434

Model override: --ai-model / $SCRYER_AI_MODEL. NOTE: with an API backend the
recon summary (target, ports, creds, findings) is sent to that third party —
your call on an authorised engagement. API keys are read from the env and never
logged.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import List, Optional

from ..core import utils
from ..core.report import HostReport

_DEFAULT_ENDPOINT = "http://localhost:11434"
_DEFAULT_OLLAMA_MODEL = "llama3.1"

# provider -> (default chat-completions URL, default model, provider-specific
# key env var). SCRYER_AI_KEY is a generic fallback used only when the provider
# is chosen explicitly, so it never hijacks auto-detection of a custom endpoint.
_PROVIDERS = {
    "deepseek": ("https://api.deepseek.com/v1/chat/completions", "deepseek-chat",
                 "DEEPSEEK_API_KEY"),
    "openai": ("https://api.openai.com/v1/chat/completions", "gpt-4o-mini",
               "OPENAI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1/chat/completions",
                   "deepseek/deepseek-chat", "OPENROUTER_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1/chat/completions",
             "llama-3.3-70b-versatile", "GROQ_API_KEY"),
}


def resolve(args) -> Optional[dict]:
    """Return the LLM backend config, or None if none is usable.

    cfg = {kind: 'api'|'ollama', name, url, model, key?}. Order: an explicitly
    chosen/keyed API provider, a custom endpoint, then a reachable local Ollama.
    """
    prov = (getattr(args, "ai_provider", None)
            or os.environ.get("SCRYER_AI_PROVIDER") or "").strip().lower()
    model = getattr(args, "ai_model", None) or os.environ.get("SCRYER_AI_MODEL")

    # explicit or key-detected OpenAI-compatible provider
    for name, (url, dmodel, keyvar) in _PROVIDERS.items():
        specific = os.environ.get(keyvar)
        if prov == name:
            keyed = specific or os.environ.get("SCRYER_AI_KEY")
        elif not prov and specific:
            keyed = specific        # auto-detect only on the provider's own key
        else:
            continue
        if keyed:
            return {"kind": "api", "name": name,
                    "url": os.environ.get("SCRYER_AI_URL") or url,
                    "model": model or dmodel, "key": keyed}
    # a fully custom endpoint
    if prov == "custom" or (not prov and os.environ.get("SCRYER_AI_URL")
                            and os.environ.get("SCRYER_AI_KEY")):
        url = os.environ.get("SCRYER_AI_URL")
        key = os.environ.get("SCRYER_AI_KEY")
        if url:
            return {"kind": "api", "name": "custom", "url": url,
                    "model": model or "default", "key": key or ""}
    # local Ollama fallback
    if not prov or prov == "ollama":
        endpoint = os.environ.get("SCRYER_OLLAMA", _DEFAULT_ENDPOINT).rstrip("/")
        if _reachable(endpoint):
            return {"kind": "ollama", "name": "ollama", "url": endpoint,
                    "model": model or _DEFAULT_OLLAMA_MODEL}
    return None


def ask(args, prompt: str) -> str:
    """One-shot query to the resolved backend. '' on any failure."""
    cfg = resolve(args)
    return _generate(cfg, prompt) if cfg else ""


def advise(host: HostReport, args) -> None:
    if not (getattr(args, "ai", False) or os.environ.get("SCRYER_AI")):
        return
    cfg = resolve(args)
    if not cfg:
        utils.log("dim", "--ai: no LLM backend — set DEEPSEEK_API_KEY / "
                         "OPENAI_API_KEY (or SCRYER_AI_URL+SCRYER_AI_KEY), or run "
                         "Ollama locally; skipping the AI advisor")
        return

    where = ("remote API" if cfg["kind"] == "api" else "local")
    utils.log("info", f"asking {cfg['name']} ({cfg['model']}, {where}) for the "
                      "next move…")
    if cfg["kind"] == "api":
        utils.log("dim", f"  (sending the recon summary to {cfg['name']} — a "
                         "third-party API)")
    answer = _generate(cfg, _build_prompt(host))
    if not answer:
        utils.log("dim", f"--ai: {cfg['name']} returned nothing (check the key / "
                         "model / connectivity)")
        return

    label = f"{cfg['name']}: {cfg['model']}"
    print("\n" + utils.c(f"┌─[ AI ADVISOR  ({label}) ]" + "─" * 16,
                        utils.C.MAGENTA, utils.C.BOLD))
    for line in answer.strip().splitlines():
        print("  " + line)
    print("  " + utils.c("(model suggestion — verify before you run it)",
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


# --------------------------------------------------------------------------
def _generate(cfg: dict, prompt: str) -> str:
    if cfg["kind"] == "ollama":
        return _ollama(cfg["url"], cfg["model"], prompt)
    return _api_chat(cfg, prompt)


def _ollama(endpoint: str, model: str, prompt: str) -> str:
    payload = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(
        f"{endpoint}/api/generate", data=payload,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return (data.get("response") or "").strip()
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        utils.log("dim", f"--ai: Ollama request failed ({str(exc)[:60]})")
        return ""


def _api_chat(cfg: dict, prompt: str) -> str:
    """OpenAI-compatible /chat/completions call (DeepSeek, OpenAI, …)."""
    payload = json.dumps({
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": "You are an expert penetration "
             "tester helping on an authorised lab machine. Be concise and "
             "give exact commands."},
            {"role": "user", "content": prompt}],
        "temperature": 0.2, "stream": False}).encode()
    headers = {"Content-Type": "application/json"}
    if cfg.get("key"):
        headers["Authorization"] = f"Bearer {cfg['key']}"
    req = urllib.request.Request(cfg["url"], data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            return (msg.get("content") or "").strip()
        err = (data.get("error") or {}).get("message", "")
        if err:
            utils.log("dim", f"--ai: {cfg['name']} API said: {err[:120]}")
        return ""
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(400).decode("utf-8", "replace")
        except Exception:
            pass
        utils.log("dim", f"--ai: {cfg['name']} API error {exc.code} "
                         f"{body[:120]}")
        return ""
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        utils.log("dim", f"--ai: {cfg['name']} request failed ({str(exc)[:60]})")
        return ""


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
