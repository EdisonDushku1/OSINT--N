#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║           OSINT--N  v1.0.0                  ║
║     All-in-ONE OSINT Toolkit                ║
║  github.com/EdisonDushku1/OSINT--N          ║
╚══════════════════════════════════════════════╝

Usage:
  python main.py --email user@example.com
  python main.py --domain example.com
  python main.py --ip 8.8.8.8
  python main.py --username targetuser
  python main.py --phone +1234567890
  python main.py --module domain --domain example.com
  python main.py --help
"""

import argparse
import json
import os
import sys
import socket
import csv
from dotenv import load_dotenv
import os

load_dotenv()  # reads .env automatically

# Then access keys like this:
HUNTER_KEY      = os.getenv("HUNTER_IO_API_KEY")
HIBP_KEY        = os.getenv("HAVEIBEENPWNED_API_KEY")
SHODAN_KEY      = os.getenv("SHODAN_API_KEY")
IPINFO_TOKEN    = os.getenv("IPINFO_TOKEN")
VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
SECURITYTRAILS  = os.getenv("SECURITYTRAILS_API_KEY")
NUMVERIFY_KEY   = os.getenv("NUMVERIFY_API_KEY")
EMAILREP_KEY    = os.getenv("EMAILREP_API_KEY")

from datetime import datetime
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
def check_deps():
    missing = []
    for pkg in ["requests", "rich", "bs4", "dns", "whois", "ipwhois", "phonenumbers"]:
        try:
            __import__(pkg if pkg != "bs4" else "bs4")
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[ERROR] Missing packages: {', '.join(missing)}")
        print("  Run: pip install -r requirements.txt")
        sys.exit(1)

check_deps()

# ── Imports ───────────────────────────────────────────────────────────────────
import requests
import dns.resolver
import whois
import phonenumbers
from phonenumbers import geocoder, carrier
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

# ── Config loader ─────────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        console.print("[bold red][!] config.json not found.[/bold red]")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

# ── Output helpers ────────────────────────────────────────────────────────────
def save_results(data: dict, target: str, module: str, config: dict):
    out_dir = Path(config["general"]["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{module}_{target.replace('@','_at_').replace('.','_')}_{timestamp}"

    formats = config["general"].get("export_formats", ["json"])

    if "json" in formats:
        path = out_dir / f"{base_name}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"  [dim]Saved → {path}[/dim]")

    if "csv" in formats:
        path = out_dir / f"{base_name}.csv"
        flat = {str(k): str(v) for k, v in data.items()}
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=flat.keys())
            writer.writeheader()
            writer.writerow(flat)
        console.print(f"  [dim]Saved → {path}[/dim]")

    if "html" in formats:
        path = out_dir / f"{base_name}.html"
        rows = "".join(
            f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
            for k, v in data.items()
        )
        html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>OSINT--N | {module} | {target}</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
table{{border-collapse:collapse;width:100%}}td{{border:1px solid #30363d;padding:.5rem .8rem}}
b{{color:#58a6ff}}h2{{color:#58a6ff}}</style></head><body>
<h2>OSINT--N — {module.upper()} report</h2>
<p>Target: <b>{target}</b> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>{rows}</table></body></html>"""
        path.write_text(html)
        console.print(f"  [dim]Saved → {path}[/dim]")


def result_table(title: str, data: dict):
    """Print a rich table from a dict."""
    t = Table(title=title, box=box.ROUNDED, border_style="cyan",
              title_style="bold cyan", show_header=True)
    t.add_column("Field", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in data.items():
        t.add_row(str(k), str(v) if v else "[dim]N/A[/dim]")
    console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
#  MODULES
# ══════════════════════════════════════════════════════════════════════════════

# ── Email ─────────────────────────────────────────────────────────────────────
def module_email(target: str, config: dict):
    console.rule(f"[bold cyan] EMAIL RECONNAISSANCE — {target}")
    data = {"target": target}

    # Basic validation
    import re
    valid = bool(re.match(r"[^@]+@[^@]+\.[^@]+", target))
    data["format_valid"] = valid
    if not valid:
        console.print("[red][!] Not a valid email format.[/red]")
        return

    domain = target.split("@")[1]
    data["domain"] = domain

    # MX records
    try:
        mx = dns.resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in mx]
        data["mx_records"] = ", ".join(mx_list)
    except Exception as e:
        data["mx_records"] = f"Error: {e}"

    # Domain exists check
    try:
        ip = socket.gethostbyname(domain)
        data["domain_ip"] = ip
        data["domain_exists"] = True
    except:
        data["domain_ip"] = "N/A"
        data["domain_exists"] = False

    # Hunter.io (if key provided)
    hunter_key = config["api_keys"].get("hunter_io", "")
    if hunter_key:
        try:
            r = requests.get(
                f"https://api.hunter.io/v2/email-verifier",
                params={"email": target, "api_key": hunter_key},
                timeout=config["general"]["timeout_seconds"]
            )
            res = r.json().get("data", {})
            data["hunter_status"]     = res.get("status", "N/A")
            data["hunter_score"]      = res.get("score", "N/A")
            data["hunter_disposable"] = res.get("disposable", "N/A")
            data["hunter_webmail"]    = res.get("webmail", "N/A")
        except Exception as e:
            data["hunter_error"] = str(e)
    else:
        data["hunter_io"] = "No API key — skipped"

    # HaveIBeenPwned
    hibp_key = config["api_keys"].get("haveibeenpwned", "")
    if hibp_key:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={"hibp-api-key": hibp_key, "User-Agent": "OSINT-N-Tool"},
                timeout=config["general"]["timeout_seconds"]
            )
            if r.status_code == 200:
                breaches = [b["Name"] for b in r.json()]
                data["breaches_found"] = len(breaches)
                data["breach_list"]    = ", ".join(breaches[:10])
            elif r.status_code == 404:
                data["breaches_found"] = 0
        except Exception as e:
            data["hibp_error"] = str(e)
    else:
        data["haveibeenpwned"] = "No API key — skipped"

    result_table("Email Reconnaissance", data)
    if config["general"]["save_results"]:
        save_results(data, target, "email", config)


# ── Domain ────────────────────────────────────────────────────────────────────
def module_domain(target: str, config: dict):
    console.rule(f"[bold cyan] DOMAIN RECONNAISSANCE — {target}")
    data = {"target": target}

    # WHOIS
    try:
        w = whois.whois(target)
        data["registrar"]    = w.registrar
        data["creation_date"]= str(w.creation_date)
        data["expiry_date"]  = str(w.expiration_date)
        data["updated_date"] = str(w.updated_date)
        data["name_servers"] = ", ".join(w.name_servers) if isinstance(w.name_servers, list) else str(w.name_servers)
        data["registrant"]   = w.name or w.org or "N/A"
        data["emails"]       = ", ".join(w.emails) if isinstance(w.emails, list) else str(w.emails)
        data["country"]      = w.country
    except Exception as e:
        data["whois_error"] = str(e)

    # DNS records
    for rtype in config.get("dns_record_types", ["A","MX","NS","TXT"]):
        try:
            answers = dns.resolver.resolve(target, rtype)
            data[f"dns_{rtype}"] = " | ".join(str(r) for r in answers)
        except:
            data[f"dns_{rtype}"] = "N/A"

    # IP
    try:
        ip = socket.gethostbyname(target)
        data["resolved_ip"] = ip
    except:
        data["resolved_ip"] = "N/A"

    # Wayback Machine
    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={target}",
            timeout=config["general"]["timeout_seconds"]
        )
        snap = r.json().get("archived_snapshots", {}).get("closest", {})
        data["wayback_available"] = snap.get("available", False)
        data["wayback_url"]       = snap.get("url", "N/A")
        data["wayback_timestamp"] = snap.get("timestamp", "N/A")
    except Exception as e:
        data["wayback_error"] = str(e)

    result_table("Domain Reconnaissance", data)
    if config["general"]["save_results"]:
        save_results(data, target, "domain", config)


# ── IP ────────────────────────────────────────────────────────────────────────
def module_ip(target: str, config: dict):
    console.rule(f"[bold cyan] IP LOOKUP — {target}")
    data = {"target": target}

    # ipwhois / RDAP
    try:
        obj = IPWhois(target)
        res = obj.lookup_rdap(depth=1)
        data["asn"]          = res.get("asn")
        data["asn_cidr"]     = res.get("asn_cidr")
        data["asn_country"]  = res.get("asn_country_code")
        data["asn_registry"] = res.get("asn_registry")
        data["asn_desc"]     = res.get("asn_description")
        net = res.get("network", {})
        data["network_name"] = net.get("name")
        data["network_cidr"] = net.get("cidr")
    except Exception as e:
        data["ipwhois_error"] = str(e)

    # ipinfo.io (free tier, no key required)
    try:
        token = config["api_keys"].get("ipinfo_token", "")
        url = f"https://ipinfo.io/{target}/json"
        if token:
            url += f"?token={token}"
        r = requests.get(url, timeout=config["general"]["timeout_seconds"])
        info = r.json()
        data["city"]     = info.get("city", "N/A")
        data["region"]   = info.get("region", "N/A")
        data["country"]  = info.get("country", "N/A")
        data["org"]      = info.get("org", "N/A")
        data["timezone"] = info.get("timezone", "N/A")
        data["loc"]      = info.get("loc", "N/A")
        data["hostname"] = info.get("hostname", "N/A")
    except Exception as e:
        data["ipinfo_error"] = str(e)

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(target)[0]
        data["reverse_dns"] = hostname
    except:
        data["reverse_dns"] = "N/A"

    result_table("IP Lookup", data)
    if config["general"]["save_results"]:
        save_results(data, target, "ip", config)


# ── Username ──────────────────────────────────────────────────────────────────
def module_username(target: str, config: dict):
    console.rule(f"[bold cyan] USERNAME SEARCH — {target}")
    data = {"target": target}
    platforms = config.get("social_media_platforms", [])

    # Build URL patterns per platform
    platform_urls = {
        "github":    f"https://github.com/{target}",
        "twitter":   f"https://twitter.com/{target}",
        "instagram": f"https://www.instagram.com/{target}/",
        "reddit":    f"https://www.reddit.com/user/{target}",
        "tiktok":    f"https://www.tiktok.com/@{target}",
        "pinterest": f"https://www.pinterest.com/{target}/",
        "twitch":    f"https://www.twitch.tv/{target}",
        "youtube":   f"https://www.youtube.com/@{target}",
        "telegram":  f"https://t.me/{target}",
    }

    found = []
    not_found = []

    headers = {"User-Agent": config.get("user_agent", "Mozilla/5.0")}
    timeout = config["general"]["timeout_seconds"]

    t = Table(title=f"Username: {target}", box=box.ROUNDED,
              border_style="cyan", title_style="bold cyan")
    t.add_column("Platform", style="bold yellow")
    t.add_column("URL", style="white")
    t.add_column("Status", style="bold")

    for platform, url in platform_urls.items():
        if platform not in platforms:
            continue
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            # Simple heuristic: 200 and URL didn't get redirected to a "not found" page
            if r.status_code == 200:
                found.append(platform)
                t.add_row(platform.capitalize(), url, "[green]✔ Found[/green]")
                data[f"{platform}_url"]    = url
                data[f"{platform}_status"] = "found"
            else:
                not_found.append(platform)
                t.add_row(platform.capitalize(), url, f"[red]✘ {r.status_code}[/red]")
                data[f"{platform}_status"] = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            t.add_row(platform.capitalize(), url, "[dim]Timeout/Error[/dim]")
            data[f"{platform}_status"] = "error"

    console.print(t)
    console.print(f"\n  [green]Found on {len(found)} platform(s)[/green] | "
                  f"[red]Not found on {len(not_found)}[/red]")
    data["found_count"]     = len(found)
    data["found_platforms"] = ", ".join(found)

    if config["general"]["save_results"]:
        save_results(data, target, "username", config)


# ── Phone ─────────────────────────────────────────────────────────────────────
def module_phone(target: str, config: dict):
    console.rule(f"[bold cyan] PHONE LOOKUP — {target}")
    data = {"target": target}
    try:
        parsed = phonenumbers.parse(target, None)
        data["valid"]         = phonenumbers.is_valid_number(parsed)
        data["possible"]      = phonenumbers.is_possible_number(parsed)
        data["country_code"]  = parsed.country_code
        data["national_num"]  = parsed.national_number
        data["region"]        = phonenumbers.region_code_for_number(parsed)
        data["location"]      = geocoder.description_for_number(parsed, "en")
        data["carrier"]       = carrier.name_for_number(parsed, "en") or "N/A"
        data["number_type"]   = str(phonenumbers.number_type(parsed))
        data["e164_format"]   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        data["intl_format"]   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    except Exception as e:
        data["error"] = str(e)
        console.print(f"[red][!] {e}[/red]")
        return

    result_table("Phone Lookup", data)
    if config["general"]["save_results"]:
        save_results(data, target, "phone", config)


# ── Subdomain ─────────────────────────────────────────────────────────────────
def module_subdomain(target: str, config: dict):
    console.rule(f"[bold cyan] SUBDOMAIN DISCOVERY — {target}")

    # Common subdomains wordlist (fallback if sublist3r not installed)
    common = ["www","mail","ftp","remote","blog","webmail","server","ns1","ns2",
              "smtp","secure","vpn","m","shop","forum","admin","portal","api",
              "dev","test","staging","app","cdn","media","static","assets"]

    found = []
    t = Table(title=f"Subdomains of {target}", box=box.ROUNDED, border_style="cyan")
    t.add_column("Subdomain", style="bold yellow")
    t.add_column("IP", style="white")

    for sub in common:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append(fqdn)
            t.add_row(fqdn, ip)
        except:
            pass

    console.print(t)
    console.print(f"\n  [green]{len(found)} subdomain(s) discovered.[/green]")

    if config["general"]["save_results"]:
        save_results({"target": target, "subdomains": ", ".join(found),
                      "count": len(found)}, target, "subdomain", config)


# ══════════════════════════════════════════════════════════════════════════════
#  BANNER & MAIN
# ══════════════════════════════════════════════════════════════════════════════

BANNER = """
[bold cyan]
  ██████╗ ███████╗██╗███╗   ██╗████████╗       ███╗   ██╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝      ████╗  ██║
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   █████╗██╔██╗ ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ╚════╝██║╚██╗██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║         ██║ ╚████║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝         ╚═╝  ╚═══╝[/bold cyan]
[dim]                  All-in-ONE OSINT Toolkit  v1.0.0[/dim]
[dim]          github.com/EdisonDushku1/OSINT--N[/dim]
"""

MODULE_MAP = {
    "email":     module_email,
    "domain":    module_domain,
    "ip":        module_ip,
    "username":  module_username,
    "phone":     module_phone,
    "subdomain": module_subdomain,
}


def main():
    parser = argparse.ArgumentParser(
        prog="OSINT--N",
        description="All-in-ONE OSINT Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--email",     metavar="EMAIL",    help="Email reconnaissance")
    parser.add_argument("--domain",    metavar="DOMAIN",   help="Domain/WHOIS/DNS recon")
    parser.add_argument("--ip",        metavar="IP",       help="IP geolocation & ASN lookup")
    parser.add_argument("--username",  metavar="USER",     help="Username search across platforms")
    parser.add_argument("--phone",     metavar="PHONE",    help="Phone number lookup (E.164 format, e.g. +1234567890)")
    parser.add_argument("--subdomain", metavar="DOMAIN",   help="Subdomain discovery")
    parser.add_argument("--module",    metavar="MODULE",
                        choices=list(MODULE_MAP.keys()),
                        help="Run a specific module by name")
    parser.add_argument("--no-save",   action="store_true",help="Do not save results to disk")

    args = parser.parse_args()

    console.print(BANNER)

    # No args → show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    config = load_config()

    if args.no_save:
        config["general"]["save_results"] = False

    # Dispatch
    dispatched = False

    if args.email:
        module_email(args.email, config)
        dispatched = True

    if args.domain:
        module_domain(args.domain, config)
        dispatched = True

    if args.ip:
        module_ip(args.ip, config)
        dispatched = True

    if args.username:
        module_username(args.username, config)
        dispatched = True

    if args.phone:
        module_phone(args.phone, config)
        dispatched = True

    if args.subdomain:
        module_subdomain(args.subdomain, config)
        dispatched = True

    # --module flag with a second positional-style target
    if args.module and not dispatched:
        console.print(f"[yellow][!] --module {args.module} specified but no target given.[/yellow]")
        console.print(f"    Example: python main.py --module {args.module} --{args.module} <target>")
        sys.exit(1)

    if not dispatched:
        parser.print_help()


if __name__ == "__main__":
    main()
