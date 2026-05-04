"""
OSINT--N | Module: Domain Reconnaissance
"""

import os
import socket
import requests
import dns.resolver
import whois
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] DOMAIN RECON — {target}")
    data = {"module": "domain", "target": target}

    # WHOIS
    try:
        w = whois.whois(target)
        data["registrar"]     = w.registrar
        data["creation_date"] = str(w.creation_date)
        data["expiry_date"]   = str(w.expiration_date)
        data["updated_date"]  = str(w.updated_date)
        data["name_servers"]  = ", ".join(w.name_servers) if isinstance(w.name_servers, list) else str(w.name_servers)
        data["registrant"]    = w.name or w.org or "N/A"
        data["country"]       = w.country or "N/A"
        data["emails"]        = ", ".join(w.emails) if isinstance(w.emails, list) else str(w.emails or "N/A")
    except Exception as e:
        data["whois_error"] = str(e)

    # DNS Records
    for rtype in config.get("dns_record_types", ["A", "AAAA", "MX", "NS", "TXT", "SOA"]):
        try:
            answers = dns.resolver.resolve(target, rtype)
            data[f"dns_{rtype}"] = " | ".join(str(r) for r in answers)
        except:
            data[f"dns_{rtype}"] = "N/A"

    # Resolved IP
    try:
        data["resolved_ip"] = socket.gethostbyname(target)
    except:
        data["resolved_ip"] = "N/A"

    # Reverse DNS
    try:
        data["reverse_dns"] = socket.gethostbyaddr(data.get("resolved_ip", ""))[0]
    except:
        data["reverse_dns"] = "N/A"

    # Wayback Machine
    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={target}",
            timeout=config["general"]["timeout_seconds"]
        ).json()
        snap = r.get("archived_snapshots", {}).get("closest", {})
        data["wayback_available"]  = snap.get("available", False)
        data["wayback_url"]        = snap.get("url", "N/A")
        data["wayback_timestamp"]  = snap.get("timestamp", "N/A")
    except Exception as e:
        data["wayback_error"] = str(e)

    # SecurityTrails — DNS history
    st_key = os.getenv("SECURITYTRAILS_API_KEY", "")
    if st_key:
        try:
            r = requests.get(
                f"https://api.securitytrails.com/v1/domain/{target}",
                headers={"APIKEY": st_key},
                timeout=config["general"]["timeout_seconds"]
            ).json()
            data["securitytrails_hostname"] = r.get("hostname", "N/A")
            data["securitytrails_alexa"]    = r.get("alexa_rank", "N/A")
        except Exception as e:
            data["securitytrails_error"] = str(e)
    else:
        data["securitytrails"] = "No API key"

    # VirusTotal
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": vt_key},
                timeout=config["general"]["timeout_seconds"]
            ).json()
            attrs = r.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            data["vt_malicious"]  = stats.get("malicious", 0)
            data["vt_suspicious"] = stats.get("suspicious", 0)
            data["vt_harmless"]   = stats.get("harmless", 0)
            data["vt_reputation"] = attrs.get("reputation", "N/A")
        except Exception as e:
            data["virustotal_error"] = str(e)
    else:
        data["virustotal"] = "No API key"

    _print_table("Domain Reconnaissance", data)
    return data


def _print_table(title, data):
    t = Table(title=title, box=box.ROUNDED, border_style="cyan", title_style="bold cyan")
    t.add_column("Field", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in data.items():
        if k == "module":
            continue
        t.add_row(str(k), str(v) if v else "[dim]N/A[/dim]")
    console.print(t)
