"""
operator.py — CLI and orchestration.

Takes a target, runs specter (passive), offers breaker (active) with
interactive confirmation per phase, writes verdict (report).
"""
from __future__ import annotations
import argparse
import asyncio
import sys
import time
from colorama import init as color_init, Fore, Style
from rich.console import Console
from rich.prompt import Confirm

from . import banner, __version__
from .spine import HttpClient, normalize_target, Finding, dedupe_findings
from . import specter, breaker, verdict


color_init(autoreset=True)
console = Console()


def say(msg, color=Fore.CYAN):
    print(f"{color}[*]{Style.RESET_ALL} {msg}")


def ok(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def bad(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


ACTIVE_CATEGORIES = {
    "sqli", "xss", "lfi", "rfi", "ssrf", "ssti", "xxe", "cmdi",
    "nosql", "crlf", "redirect", "brute", "jwt",
}


async def run_specter(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    def progress(name):
        say(f"specter · {name}")
    return await specter.run(client, target, progress)


async def run_breaker(client: HttpClient, target: dict, data: dict,
                      selected: set[str]) -> tuple[list[Finding], dict]:
    def progress(name):
        say(f"breaker · {name}")
    return await breaker.run(client, target, data, progress, selected)


def _ask_active_selection() -> set[str]:
    console.print()
    console.print("[bold]Active testing phases available[/bold] (only run with confirmation):")
    console.print("  sqli   xss   lfi   rfi   ssrf   ssti   xxe   cmdi")
    console.print("  nosql  crlf  redirect   brute   jwt")
    console.print()
    if not Confirm.ask("[yellow]Run active tests?[/]", default=False):
        return set()
    selected = set()
    for cat in ACTIVE_CATEGORIES:
        if Confirm.ask(f"  → test [cyan]{cat}[/]?", default=(cat in ("sqli", "xss", "lfi"))):
            selected.add(cat)
    return selected


async def main_async(args):
    target = normalize_target(args.target)
    say(f"target: {target['base_url']}")
    say(f"root domain: {target['root_domain']}")
    console.print()

    all_findings: list[Finding] = []
    data: dict = {}

    async with HttpClient(verify=False,
                          concurrency=args.concurrency) as client:
        # passive
        say("starting passive reconnaissance")
        t0 = time.monotonic()
        findings, data = await run_specter(client, target)
        all_findings.extend(findings)
        elapsed = time.monotonic() - t0
        ok(f"passive done in {elapsed:.1f}s — {len(findings)} findings")

        # active
        selected = set()
        if not args.json_only:
            selected = _ask_active_selection()
        elif args.active:
            selected = ACTIVE_CATEGORIES

        if selected:
            say(f"starting active testing: {', '.join(sorted(selected))}")
            t0 = time.monotonic()
            findings2, active_data = await run_breaker(client, target, data, selected)
            all_findings.extend(findings2)
            data["active"] = active_data
            elapsed = time.monotonic() - t0
            ok(f"active done in {elapsed:.1f}s — {len(findings2)} findings")

    # dedupe
    all_findings = dedupe_findings(all_findings)

    # report
    say("writing report")
    paths = verdict.write_reports(target, data, all_findings, args.output, __version__)
    print()
    ok(f"summary: {paths['summary']}")
    ok(f"json:    {paths['json']}")
    ok(f"html:    {paths['html']}")


def main():
    banner()
    parser = argparse.ArgumentParser(
        prog="atomic",
        description="ATOMIC — reconnaissance & assessment toolkit",
    )
    parser.add_argument("target", help="example.com or https://example.com/")
    parser.add_argument("-o", "--output", default="atomic_out",
                        help="output directory (default atomic_out)")
    parser.add_argument("--concurrency", type=int, default=60,
                        help="max concurrent HTTP requests (default 60)")
    parser.add_argument("--active", action="store_true",
                        help="run all active tests without interactive prompts")
    parser.add_argument("--json-only", action="store_true",
                        help="passive only, no prompts")
    args = parser.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        bad("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
