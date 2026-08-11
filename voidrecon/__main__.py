"""Command-line interface for voidrecon.

Usage:
    python -m voidrecon <target> [options]
"""

from __future__ import annotations

import argparse
import os
import sys

from .core import utils
from .core.engine import Engine
from .core import report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="voidrecon",
        description="Deep, adaptive recon for CTF / lab targets (HTB, THM, etc.).",
        epilog="Only scan hosts you are explicitly authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="IP address or hostname to recon")
    p.add_argument("-p", "--ports", default="top",
                   help="'top' (default), 'full' (1-65535), or a list like "
                        "'22,80,443,8000-8100'")
    p.add_argument("-t", "--timeout", type=float, default=1.5,
                   help="per-port connect timeout in seconds (default 1.5)")
    p.add_argument("-w", "--workers", type=int, default=200,
                   help="concurrent scan threads (default 200)")
    p.add_argument("--nmap", action="store_true",
                   help="use nmap -sV for service/version + OS detection if installed")
    p.add_argument("--nmap-timeout", type=int, default=300,
                   help="timeout for the nmap phase (default 300s)")
    p.add_argument("-o", "--output", metavar="DIR",
                   help="write JSON + Markdown reports into DIR")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print the final summary")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color:
        utils.C.disable()

    if not args.quiet:
        print(utils.banner())
        utils.log("info", f"target: {utils.c(args.target, utils.C.CYAN, utils.C.BOLD)}")
        utils.log("warn", "authorized targets only — you own the consequences")

    if args.quiet:
        # Suppress the phase chatter by swallowing stdout from utils.log.
        _silence_progress()

    with utils.Timer() as timer:
        engine = Engine(args.target, args)
        host = engine.run()

    if args.quiet:
        _restore_progress()

    report.summarize_console(host)
    utils.log("info", f"completed in {timer}")

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        safe = args.target.replace("/", "_").replace(":", "_")
        json_path = os.path.join(args.output, f"{safe}.json")
        md_path = os.path.join(args.output, f"{safe}.md")
        report.to_json(host, json_path)
        report.to_markdown(host, md_path)
        utils.log("good", f"reports written: {json_path} , {md_path}")

    # Non-zero exit if nothing actionable, handy for scripting.
    notable = [f for f in host.findings if f.severity in ("critical", "high")]
    return 0 if host.open_ports else 2


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
