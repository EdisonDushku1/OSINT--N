"""
OSINT--N | Module: Email Reconnaissance
MX + SPF + DKIM + DMARC + Hunter.io + HaveIBeenPwned + EmailRep
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

# Common disposable email providers
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwam.com", "fakeinbox.com", "yopmail.com", "sharklasers.com",
    "trashmail.com", "maildrop.cc", "getairmail.com", "dispostable.com",
    "temp-mail.org", "throwaway.email", "spamgourmet.com", "mytemp.email",
    "spamex.com", "mailnull.com", "boun.cr", "spamevader.com",
}

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] EMAIL RECON — {target}")
    data = {"module": "email", "target": target}
    timeout = config["general"]["timeout_seconds"]

    # Format check
    if not re.match(r"[^@]+@[^@]+\.[^@]+", target):
        console.print("[red][!] Invalid email format.[/red]")
        return data

    domain = target.split("@")[1]
    data["domain"] = domain

    # ── Disposable check (offline) ────────────
    data["disposable_email"] = domain.lower() in DISPOSABLE_DOMAINS
    if data["disposable_email"]:
        console.print(f"\n  [bold red][!] This is a known DISPOSABLE email domain![/bold red]\n")

    # ── MX Records ───────────────────────────
    try:
        mx = dns.resolver.resolve(domain, "MX")
        data["mx_records"] = " | ".join(
            f"{r.preference} {str(r.exchange).rstrip('.')}" for r in sorted(mx, key=lambda x: x.preference)
        )
    except Exception:
        data["mx_records"] = "N/A — domain may not accept email"

    # ── Domain IP ────────────────────────────
    try:
        data["domain_ip"]     = socket.gethostbyname(domain)
        data["domain_exists"] = True
    except Exception:
        data["domain_ip"]     = "N/A"
        data["domain_exists"] = False

    # ── SPF Record ───────────────────────────
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        spf = [str(r) for r in txt_records if "v=spf1" in str(r).lower()]
        data["spf_record"] = spf[0] if spf else "MISSING — spoofing possible"
    except Exception:
        data["spf_record"] = "N/A"

    # ── DMARC Record ─────────────────────────
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in dmarc]
        if dmarc_records:
            data["dmarc_record"] = dmarc_records[0]
            # Extract policy
            for part in dmarc_records[0].split(";"):
                if "p=" in part.lower():
                    policy = part.strip().split("=")[1].strip().strip('"')
                    data["dmarc_policy"] = policy
                    if policy == "none":
                        data["dmarc_enforcement"] = "⚠ Monitor only — not enforced"
                    elif policy == "quarantine":
                        data["dmarc_enforcement"] = "✔ Quarantine enforced"
                    elif policy == "reject":
                        data["dmarc_enforcement"] = "✔✔ Reject enforced (strongest)"
        else:
            data["dmarc_record"] = "MISSING"
    except Exception:
        data["dmarc_record"] = "MISSING — no DMARC policy"

    # ── DKIM check (common selectors) ────────
    dkim_selectors = ["default", "google", "k1", "selector1", "selector2", "mail", "dkim"]
    found_dkim = []
    for sel in dkim_selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            found_dkim.append(sel)
        except Exception:
            pass
    data["dkim_selectors_found"] = ", ".join(found_dkim) if found_dkim else "None detected with common selectors"

    # ── Hunter.io ─────────────────────────────
    key = os.getenv("HUNTER_IO_API_KEY", "")
    if key:
        try:
            r = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": target, "api_key": key},
                timeout=timeout,
            ).json().get("data", {})
            data["hunter_status"]     = r.get("status", "N/A")
            data["hunter_score"]      = r.get("score", "N/A")
            data["hunter_disposable"] = r.get("disposable", False)
            data["hunter_webmail"]    = r.get("webmail", False)
            data["hunter_smtp_valid"] = r.get("smtp_server", False)
        except Exception as e:
            data["hunter_error"] = str(e)
    else:
        data["hunter_io"] = "No API key (add HUNTER_IO_API_KEY to .env)"

    # ── HaveIBeenPwned ────────────────────────
    hibp = os.getenv("HAVEIBEENPWNED_API_KEY", "")
    if hibp:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={"hibp-api-key": hibp, "User-Agent": "OSINT-N"},
                timeout=timeout,
            )
            if r.status_code == 200:
                breaches = [b["Name"] for b in r.json()]
                data["breaches_found"] = len(breaches)
                data["breach_names"]   = ", ".join(breaches[:15])
                if breaches:
                    console.print(f"\n  [bold red][!] Found in {len(breaches)} breach(es)![/bold red]\n")
            else:
                data["breaches_found"] = 0
                data["breach_names"]   = "Clean"
        except Exception as e:
            data["hibp_error"] = str(e)
    else:
        data["haveibeenpwned"] = "No API key (add HAVEIBEENPWNED_API_KEY to .env)"

    # ── EmailRep ──────────────────────────────
    erep = os.getenv("EMAILREP_API_KEY", "")
    if erep:
        try:
            r = requests.get(
                f"https://emailrep.io/{target}",
                headers={"Key": erep, "User-Agent": "OSINT-N"},
                timeout=timeout,
            ).json()
            data["emailrep_reputation"] = r.get("reputation", "N/A")
            data["emailrep_suspicious"] = r.get("suspicious", "N/A")
            data["emailrep_references"] = r.get("references", "N/A")
            data["emailrep_profiles"]   = ", ".join(r.get("details", {}).get("profiles", [])) or "N/A"
        except Exception as e:
            data["emailrep_error"] = str(e)
    else:
        data["emailrep"] = "No API key (add EMAILREP_API_KEY to .env)"

    _print_table("Email Reconnaissance", data)
    return data


def _print_table(title, data):
    t = Table(title=title, box=box.ROUNDED, border_style="cyan", title_style="bold cyan")
    t.add_column("Field", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in data.items():
        if k in ("module",):
            continue
        val = str(v) if v else "[dim]N/A[/dim]"
        if "MISSING" in val or "spoofing" in val:
            val = f"[red]{val}[/red]"
        elif "✔" in val:
            val = f"[green]{val}[/green]"
        t.add_row(str(k), val)
    console.print(t)
