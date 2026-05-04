#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# rest of the code continues below...
"""
╔══════════════════════════════════════════════╗
║           OSINT--N  v2.0.0                  ║
║       All-in-ONE OSINT Toolkit              ║
║  github.com/BlindFoldee/OSINT--N          ║
╚══════════════════════════════════════════════╝
"""

import argparse
import json
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        print("[!] config.json not found.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

# ── Rich ──────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich import box
except ImportError:
    print("[!] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# ── Modules ───────────────────────────────────
from modules import (
    email_recon,
    domain_recon,
    ip_lookup,
    username_search,
    phone_lookup,
    subdomain_scan,
    metadata_extractor,
    reporter,
)

BANNER = """[bold cyan]
  ██████╗ ███████╗██╗███╗   ██╗████████╗      ███╗   ██╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝     ████╗  ██║
 ██║   ██║███████╗██║██╔██╗ ██║   ██║  █████╗██╔██╗ ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║  ╚════╝██║╚██╗██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║        ██║ ╚████║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═╝  ╚═══╝[/bold cyan]
[dim]              All-in-ONE OSINT Toolkit  v2.0.0[/dim]
[dim]       github.com/BlindFoldee/OSINT--N[/dim]
"""

MENU = """
  [bold cyan][1][/bold cyan]  Email Reconnaissance
  [bold cyan][2][/bold cyan]  Domain / WHOIS / DNS Recon
  [bold cyan][3][/bold cyan]  IP Lookup + Geolocation
  [bold cyan][4][/bold cyan]  Username Search (20+ platforms)
  [bold cyan][5][/bold cyan]  Phone Number Lookup
  [bold cyan][6][/bold cyan]  Subdomain Discovery
  [bold cyan][7][/bold cyan]  Image Metadata / EXIF Extractor
  [bold red][0][/bold red]  Exit
"""

MODULE_MAP = {
    "1": ("email",     email_recon,        "email",     "Enter email address"),
    "2": ("domain",    domain_recon,       "domain",    "Enter domain (e.g. example.com)"),
    "3": ("ip",        ip_lookup,          "ip",        "Enter IP address"),
    "4": ("username",  username_search,    "username",  "Enter username"),
    "5": ("phone",     phone_lookup,       "phone",     "Enter phone number (e.g. +1234567890)"),
    "6": ("subdomain", subdomain_scan,     "subdomain", "Enter domain to enumerate"),
    "7": ("metadata",  metadata_extractor, "metadata",  "Enter image path or URL"),
}


def run_module(key: str, target: str, config: dict):
    if key not in MODULE_MAP:
        console.print("[red][!] Unknown module.[/red]")
        return
    _, mod, _, _ = MODULE_MAP[key]
    data = mod.run(target, config)
    reporter.save(data, config)


def interactive_mode(config: dict):
    console.print(BANNER)
    while True:
        console.print(Panel(MENU, title="[bold cyan]Select Module[/bold cyan]",
                            border_style="cyan", padding=(0, 2)))
        choice = Prompt.ask("[bold yellow]OSINT--N[/bold yellow]", default="0").strip()

        if choice == "0":
            console.print("\n[dim]Goodbye.[/dim]\n")
            break

        if choice not in MODULE_MAP:
            console.print("[red][!] Invalid choice.[/red]\n")
            continue

        _, _, _, prompt_text = MODULE_MAP[choice]
        target = Prompt.ask(f"[cyan]{prompt_text}[/cyan]").strip()
        if not target:
            console.print("[red][!] No target entered.[/red]\n")
            continue

        console.print()
        run_module(choice, target, config)
        console.print()


def cli_mode(args, config: dict):
    console.print(BANNER)

    flag_to_key = {
        "email":     "1",
        "domain":    "2",
        "ip":        "3",
        "username":  "4",
        "phone":     "5",
        "subdomain": "6",
        "metadata":  "7",
    }

    dispatched = False
    for flag, key in flag_to_key.items():
        val = getattr(args, flag, None)
        if val:
            run_module(key, val, config)
            dispatched = True

    if not dispatched:
        console.print("[yellow][!] No target specified. Use --help or run without flags for interactive mode.[/yellow]")


def main():
    parser = argparse.ArgumentParser(
        prog="OSINT--N",
        description="All-in-ONE OSINT Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--email",     metavar="EMAIL",   help="Email reconnaissance")
    parser.add_argument("--domain",    metavar="DOMAIN",  help="Domain/WHOIS/DNS recon")
    parser.add_argument("--ip",        metavar="IP",      help="IP geolocation & ASN lookup")
    parser.add_argument("--username",  metavar="USER",    help="Username search (20+ platforms)")
    parser.add_argument("--phone",     metavar="PHONE",   help="Phone number lookup")
    parser.add_argument("--subdomain", metavar="DOMAIN",  help="Subdomain discovery")
    parser.add_argument("--metadata",  metavar="FILE/URL",help="Image metadata / EXIF extractor")
    parser.add_argument("--no-save",   action="store_true", help="Do not save results to disk")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive menu")

    args = parser.parse_args()
    config = load_config()

    if args.no_save:
        config["general"]["save_results"] = False

    # No flags = interactive
    if len(sys.argv) == 1 or args.interactive:
        interactive_mode(config)
    else:
        cli_mode(args, config)


if __name__ == "__main__":
    main()
