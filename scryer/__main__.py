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

    if not args.target:
        build_parser().error("a target is required (or use --toolcheck)")

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
