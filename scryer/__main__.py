"""Command-line interface for scryer.

Usage:
    python -m scryer <target> [options]
    python -m scryer --toolcheck [--install]
"""

from __future__ import annotations

import argparse
import os
import sys

from .core import utils, tooling, playbook
from .core.engine import Engine
from .core import report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scryer",
        description="Deep, adaptive recon for CTF / lab targets (HTB, THM, etc.).",
        epilog="Only scan hosts you are explicitly authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?",
                   help="IP address or hostname to recon")

    scan = p.add_argument_group("scanning")
    scan.add_argument("-p", "--ports", default="top",
                      help="'top' (default), 'full' (1-65535), or a list like "
                           "'22,80,443,8000-8100'")
    scan.add_argument("--udp", action="store_true",
                      help="also scan top UDP ports (nmap, needs root for accuracy)")
    scan.add_argument("--no-nmap", action="store_true",
                      help="force the pure-python scanner even if nmap is present")
    scan.add_argument("-t", "--timeout", type=float, default=1.5,
                      help="python-scan per-port connect timeout (default 1.5s)")
    scan.add_argument("-w", "--workers", type=int, default=200,
                      help="python-scan concurrent threads (default 200)")
    scan.add_argument("--nmap-timeout", type=int, default=900,
                      help="timeout for each nmap phase (default 900s)")

    web = p.add_argument_group("web / vhost")
    web.add_argument("-D", "--vhost-domain", metavar="DOMAIN",
                     help="base domain for virtual-host brute forcing, e.g. "
                          "'nexus.htb' (auto-derived from discovered hostnames)")
    web.add_argument("--no-vhost", action="store_true",
                     help="skip virtual-host / subdomain brute forcing")
    web.add_argument("--add-hosts", action="store_true",
                     help="auto-add discovered vhosts to /etc/hosts (uses sudo "
                          "if needed) so external tools + browser resolve them")
    web.add_argument("--web-brute", action="store_true",
                     help="run a full wordlist dir brute (feroxbuster/ffuf + "
                          "SecLists) per web port — slow and loud")
    web.add_argument("--params", action="store_true",
                     help="run paramvoid parameter discovery on web endpoints "
                          "(implied by --web-brute)")
    web.add_argument("--mail-spray", action="store_true",
                     help="replay recovered passwords across the full first-name "
                          "list over IMAP/POP3 (loud — can trip Dovecot/fail2ban "
                          "rate-limiting). Off by default: only the accounts the "
                          "box named, plus colleagues found in an opened mailbox, "
                          "are tried")

    art = p.add_argument_group("offline artifacts (Jeopardy CTF)")
    art.add_argument("--file", metavar="PATH",
                     help="analyze a local challenge file instead of a host: "
                          "pcap/pcapng (traffic + creds + carved objects), "
                          "zip/tar/kdbx (crack + extract + scan), or any other "
                          "file (forensic strings/stego + layered decode). "
                          "No network recon is run.")
    art.add_argument("--decode", metavar="STRING",
                     help="peel encoding layers off STRING (base64/32/16/85, "
                          "hex, URL, gzip, ROT-N, Atbash, single-byte XOR) and "
                          "print any flag found. No target needed.")
    art.add_argument("--flag-format", metavar="PREFIX",
                     help="the event's flag prefix, e.g. 'securewv' — improves "
                          "ROT/XOR brute filtering during decode/artifact runs")
    art.add_argument("--connect", metavar="HOST:PORT",
                     help="open an interactive nc-style session to a challenge "
                          "service: relays your terminal, watches the stream for "
                          "flags, and auto-answers arithmetic/proof-of-work "
                          "prompts. No target needed.")
    art.add_argument("--no-auto", action="store_true",
                     help="with --connect: raw relay only (disable the "
                          "arithmetic/PoW auto-solver)")

    ai = p.add_argument_group("agent / AI advisor (Ollama or an API key)")
    ai.add_argument("--ai", action="store_true",
                    help="ask an LLM to read the recon state and recommend the "
                         "next exploitation step. Uses a local Ollama by default; "
                         "or set an API key (DEEPSEEK_API_KEY / OPENAI_API_KEY, "
                         "or SCRYER_AI_URL+SCRYER_AI_KEY). Also enabled by "
                         "SCRYER_AI=1.")
    ai.add_argument("--ai-provider", metavar="NAME", default=None,
                    choices=["ollama", "deepseek", "openai", "openrouter",
                             "groq", "custom"],
                    help="force the LLM backend (default: auto-detect from the "
                         "environment). One of: ollama, deepseek, openai, "
                         "openrouter, groq, custom.")
    ai.add_argument("--ai-model", metavar="NAME", default=None,
                    help="model name (default: the provider's default, or "
                         "$SCRYER_AI_MODEL) — e.g. deepseek-chat, gpt-4o-mini")
    ai.add_argument("--agent", action="store_true",
                    help="autonomous execution loop: the local LLM proposes the "
                         "next command, scryer safety-checks and runs it, scans "
                         "the output for flags/creds, and iterates. Needs "
                         "Ollama. Confirms each command unless --agent-auto.")
    ai.add_argument("--agent-auto", action="store_true",
                    help="with --agent: run each allowlisted command without "
                         "asking (hands-off). Authorized targets only.")
    ai.add_argument("--agent-steps", type=int, default=6, metavar="N",
                    help="max agent-loop iterations (default 6)")

    exp = p.add_argument_group("exploitation (active — authorized targets only)")
    exp.add_argument("--exploit", action="store_true",
                     help="enable active exploit chains: writable S3 bucket -> "
                          "webshell -> RCE -> flag; and log in with any "
                          "recovered credential, crawl the authenticated area, "
                          "and drive sqlmap --os-cmd to a shell + flags. "
                          "Read-only recon (S3 listing, cracking) runs without "
                          "this flag.")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="DIR",
                     help="write JSON + Markdown reports and commands.sh into DIR")
    out.add_argument("--no-searchsploit", action="store_true",
                     help="skip the searchsploit exploit-lookup phase")
    out.add_argument("--no-color", action="store_true", help="disable colored output")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="only print the final summary + next steps")

    tools = p.add_argument_group("tooling")
    tools.add_argument("--toolcheck", action="store_true",
                       help="audit which external tools are installed, then exit")
    tools.add_argument("--install", action="store_true",
                       help="with --toolcheck: install the missing tools")
    tools.add_argument("-y", "--yes", action="store_true",
                       help="assume yes for --install prompts")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color:
        utils.C.disable()

    # Tooling audit / install is a standalone mode — no target required.
    if args.toolcheck:
        tooling.system_check()
        if args.install:
            tooling.install_missing(assume_yes=args.yes)
        return 0

    # Offline artifact / decode modes — no host, no network recon.
    if args.flag_format:
        from .modules import crypto
        crypto.set_flag_prefix(args.flag_format)
    if args.decode:
        from .modules import artifact
        if not args.quiet:
            print(utils.banner())
        flags = artifact.decode(args.decode)
        return 0 if flags else 2
    if args.file:
        from .modules import artifact
        if not args.quiet:
            print(utils.banner())
        flags = artifact.analyze(args.file)
        return 0 if flags else 2
    if args.connect:
        from .modules import connect
        if not args.quiet:
            print(utils.banner())
        flags = connect.connect(args.connect, auto=not args.no_auto)
        return 0 if flags else 2

    if not args.target:
        build_parser().error("a target is required (or use --toolcheck, "
                             "--file, or --decode)")

    if not args.quiet:
        print(utils.banner())
        utils.log("info", f"target: {utils.c(args.target, utils.C.CYAN, utils.C.BOLD)}")
        _engine_line(args)
        utils.log("warn", "authorized targets only — you own the consequences")

    if args.quiet:
        _silence_progress()

    with utils.Timer() as timer:
        engine = Engine(args.target, args)
        host = engine.run()

    if args.quiet:
        _restore_progress()

    report.summarize_console(host)

    # Ranked ATTACK PLAN (the brain) — the few highest-leverage moves first,
    # with an optional local-LLM advisor folded in when one is available.
    from .core import brain
    brain.render_console(host)
    from .modules import aiadvisor
    aiadvisor.advise(host, args)

    # Autonomous execution loop (opt-in, allowlisted, confirmation-first).
    from .modules import agent
    agent.run(host, args)

    # Build the copy-paste next-step playbook.
    pb = playbook.Playbook(host).build()
    pb.render_console()

    utils.log("info", f"completed in {timer}")

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        safe = args.target.replace("/", "_").replace(":", "_")
        json_path = os.path.join(args.output, f"{safe}.json")
        md_path = os.path.join(args.output, f"{safe}.md")
        sh_path = os.path.join(args.output, f"{safe}.commands.sh")
        report.to_json(host, json_path)
        report.to_markdown(host, md_path)
        pb.write_script(sh_path)
        utils.log("good", f"written: {json_path} , {md_path} , {sh_path}")

    return 0 if host.open_ports else 2


def _engine_line(args) -> None:
    scanner = "python" if args.no_nmap or not tooling.resolve("nmap") else "nmap"
    if not args.no_nmap and tooling.resolve("rustscan"):
        scanner = "rustscan+nmap"
    present = sum(1 for t in tooling.REGISTRY if t.available())
    utils.log("info", f"scan engine: {utils.c(scanner, utils.C.CYAN)}  "
                      f"({present}/{len(tooling.REGISTRY)} tools available — "
                      f"`scryer --toolcheck` for details)")


# -- quiet-mode plumbing ----------------------------------------------------
_orig = {"log": utils.log, "section": utils.section, "kv": utils.kv}


def _silence_progress() -> None:
    noop = lambda *a, **k: None  # noqa: E731
    utils.log = noop      # type: ignore
    utils.section = noop  # type: ignore
    utils.kv = noop       # type: ignore


def _restore_progress() -> None:
    utils.log, utils.section, utils.kv = (  # type: ignore
        _orig["log"], _orig["section"], _orig["kv"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n" + utils.c("[!] interrupted", utils.C.YELLOW))
        sys.exit(130)
