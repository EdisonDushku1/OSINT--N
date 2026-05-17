#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        print("[!] config.json not found.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError:
    print("[!] Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

from modules import (
    email_recon,
    domain_recon,
    ip_lookup,
    username_search,
    phone_lookup,
    subdomain_scan,
    metadata_extractor,
    port_scan,
    reporter,
)

BANNER = """[bold cyan]
  ██████╗ ███████╗██╗███╗   ██╗████████╗      ███╗   ██╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝     ████╗  ██║
 ██║   ██║███████╗██║██╔██╗ ██║   ██║  █████╗██╔██╗ ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║  ╚════╝██║╚██╗██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║        ██║ ╚████║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═╝  ╚═══╝[/bold cyan]
[dim]              All-in-ONE OSINT Toolkit  v3.0.0[/dim]
[dim]       github.com/EdisonDushku1/OSINT--N[/dim]
"""

MENU = """
  [bold cyan][1][/bold cyan]  Email Reconnaissance
  [bold cyan][2][/bold cyan]  Domain / WHOIS / DNS / SSL Recon
  [bold cyan][3][/bold cyan]  IP Lookup + Geolocation + Threat Intel
  [bold cyan][4][/bold cyan]  Username Search (50+ platforms)
  [bold cyan][5][/bold cyan]  Phone Number Lookup
  [bold cyan][6][/bold cyan]  Subdomain Discovery (crt.sh + wordlist)
  [bold cyan][7][/bold cyan]  Image Metadata / EXIF Extractor
  [bold cyan][8][/bold cyan]  Port Scanner (TCP Async)
  [bold red][0][/bold red]  Exit
"""

MODULE_MAP = {
    "1": ("email",     email_recon,        "email",     "Enter email address"),
    "2": ("domain",    domain_recon,       "domain",    "Enter domain (e.g. example.com)"),
    "3": ("ip",        ip_lookup,          "ip",        "Enter IP address or hostname"),
    "4": ("username",  username_search,    "username",  "Enter username"),
    "5": ("phone",     phone_lookup,       "phone",     "Enter phone number (e.g. +1234567890)"),
    "6": ("subdomain", subdomain_scan,     "subdomain", "Enter domain to enumerate"),
    "7": ("metadata",  metadata_extractor, "metadata",  "Enter image path or URL"),
    "8": ("portscan",  port_scan,          "portscan",  "Enter host/IP to scan"),
}

API_KEYS = {
    "HUNTER_IO_API_KEY":       "Hunter.io (Email)",
    "HAVEIBEENPWNED_API_KEY":  "HaveIBeenPwned",
    "EMAILREP_API_KEY":        "EmailRep",
    "VIRUSTOTAL_API_KEY":      "VirusTotal",
    "SECURITYTRAILS_API_KEY":  "SecurityTrails",
    "NUMVERIFY_API_KEY":       "NumVerify (Phone)",
    "ABUSEIPDB_API_KEY":       "AbuseIPDB",
    "SHODAN_API_KEY":          "Shodan",
}

def print_api_status():
    t = Table(
        title="API Key Status",
        box=box.SIMPLE_HEAD,
        border_style="dim",
        title_style="bold dim",
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
    )
    t.add_column("Service", style="yellow", no_wrap=True)
    t.add_column("Status", justify="center")
    for env_key, label in API_KEYS.items():
        val = os.getenv(env_key, "")
        if val and val.strip() and val != "YOUR_KEY_HERE":
            t.add_row(label, "[green]✔ Active[/green]")
        else:
            t.add_row(label, "[red dim]✘ Missing[/red dim]")
    console.print(t)
    console.print("[dim]  → Add API keys to your .env file for full coverage[/dim]\n")

def run_module(key: str, target: str, config: dict):
    if key not in MODULE_MAP:
        console.print("[red][!] Unknown module.[/red]")
        return
    _, mod, name, _ = MODULE_MAP[key]
    with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]{task.description}"), transient=True, console=console) as p:
        task = p.add_task(f"Running {name} recon on {target}...", total=None)
        data = mod.run(target, config)
        p.remove_task(task)
    reporter.save(data, config)

def interactive_mode(config: dict):
    console.print(BANNER)
    print_api_status()
    while True:
        console.print(Panel(MENU, title="[bold cyan]Select Module[/bold cyan]", border_style="cyan", padding=(0, 2)))
        choice = Prompt.ask("[bold yellow]OSINT--N[/bold yellow]", default="0").strip()
        if choice == "0":
            console.print("\n[dim]Goodbye. Stay curious.[/dim]\n")
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
    print_api_status()
    flag_to_key = {
        "email": "1", "domain": "2", "ip": "3", "username": "4",
        "phone": "5", "subdomain": "6", "metadata": "7", "portscan": "8",
    }
    dispatched = False
    for flag, key in flag_to_key.items():
        val = getattr(args, flag, None)
        if val:
            run_module(key, val, config)
            dispatched = True
    if not dispatched:
        console.print("[yellow][!] No target specified. Use --help or run without flags.[/yellow]")

def main():
    parser = argparse.ArgumentParser(prog="OSINT--N", description="All-in-ONE OSINT Toolkit v3.0.0", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--email",     metavar="EMAIL",    help="Email reconnaissance")
    parser.add_argument("--domain",    metavar="DOMAIN",   help="Domain/WHOIS/DNS/SSL recon")
    parser.add_argument("--ip",        metavar="IP",       help="IP geolocation, ASN & threat intel")
    parser.add_argument("--username",  metavar="USER",     help="Username search (50+ platforms)")
    parser.add_argument("--phone",     metavar="PHONE",    help="Phone number lookup")
    parser.add_argument("--subdomain", metavar="DOMAIN",   help="Subdomain discovery")
    parser.add_argument("--metadata",  metavar="FILE/URL", help="Image metadata / EXIF extractor")
    parser.add_argument("--portscan",  metavar="HOST",     help="Async TCP port scanner")
    parser.add_argument("--no-save",   action="store_true", help="Do not save results to disk")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive menu")
    parser.add_argument("--version", "-v", action="version", version="OSINT--N v3.0.0")
    args = parser.parse_args()
    config = load_config()
    if args.no_save:
        config["general"]["save_results"] = False
    if len(sys.argv) == 1 or args.interactive:
        interactive_mode(config)
    else:
        cli_mode(args, config)

if __name__ == "__main__":
    main()
    
