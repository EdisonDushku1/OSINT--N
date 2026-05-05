"""
OSINT--N | Module: Email Reconnaissance
"""

import os
import re
import socket
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] EMAIL RECON — {target}")
    data = {"module": "email", "target": target}

    # Format check
    if not re.match(r"[^@]+@[^@]+\.[^@]+", target):
        console.print("[red][!] Invalid email format.[/red]")
        return data

    domain = target.split("@")[1]
    data["domain"] = domain

    # MX Records
    try:
        mx = dns.resolver.resolve(domain, "MX")
        data["mx_records"] = " | ".join(str(r.exchange).rstrip(".") for r in mx)
    except:
        data["mx_records"] = "N/A"

    # Domain IP
    try:
        data["domain_ip"]     = socket.gethostbyname(domain)
        data["domain_exists"] = True
    except:
        data["domain_ip"]     = "N/A"
        data["domain_exists"] = False

    # Hunter.io
    key = os.getenv("HUNTER_IO_API_KEY", "")
    if key:
        try:
            r = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": target, "api_key": key},
                timeout=config["general"]["timeout_seconds"]
            ).json().get("data", {})
            data["hunter_status"]     = r.get("status", "N/A")
            data["hunter_score"]      = r.get("score", "N/A")
            data["hunter_disposable"] = r.get("disposable", False)
            data["hunter_webmail"]    = r.get("webmail", False)
        except Exception as e:
            data["hunter_error"] = str(e)
    else:
        data["hunter_io"] = "No API key"

    # HaveIBeenPwned
    hibp = os.getenv("HAVEIBEENPWNED_API_KEY", "")
    if hibp:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={"hibp-api-key": hibp, "User-Agent": "OSINT-N"},
                timeout=config["general"]["timeout_seconds"]
            )
            if r.status_code == 200:
                breaches = [b["Name"] for b in r.json()]
                data["breaches_found"] = len(breaches)
                data["breach_names"]   = ", ".join(breaches[:15])
            else:
                data["breaches_found"] = 0
        except Exception as e:
            data["hibp_error"] = str(e)
    else:
        data["haveibeenpwned"] = "No API key"

    # EmailRep
    erep = os.getenv("EMAILREP_API_KEY", "")
    if erep:
        try:
            r = requests.get(
                f"https://emailrep.io/{target}",
                headers={"Key": erep, "User-Agent": "OSINT-N"},
                timeout=config["general"]["timeout_seconds"]
            ).json()
            data["emailrep_reputation"] = r.get("reputation", "N/A")
            data["emailrep_suspicious"] = r.get("suspicious", "N/A")
            data["emailrep_references"] = r.get("references", "N/A")
        except Exception as e:
            data["emailrep_error"] = str(e)
    else:
        data["emailrep"] = "No API key"

    _print_table("Email Reconnaissance", data)
    return data


def _print_table(title, data):
    t = Table(title=title, box=box.ROUNDED, border_style="cyan", title_style="bold cyan")
    t.add_column("Field", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in data.items():
        if k in ("module",):
            continue
        t.add_row(str(k), str(v) if v else "[dim]N/A[/dim]")
    console.print(t)
