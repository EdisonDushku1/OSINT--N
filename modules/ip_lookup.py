"""
OSINT--N | Module: IP Lookup + Geolocation
"""

import os
import socket
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] IP LOOKUP — {target}")
    data = {"module": "ip", "target": target}

    try:
        resolved = socket.gethostbyname(target)
        if resolved != target:
            data["resolved_ip"] = resolved
        ip = resolved
    except Exception as e:
        data["resolve_error"] = str(e)
        ip = target

    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=config["general"]["timeout_seconds"]
        ).json()
        data["ip"]       = r.get("ip", "N/A")
        data["hostname"] = r.get("hostname", "N/A")
        data["city"]     = r.get("city", "N/A")
        data["region"]   = r.get("region", "N/A")
        data["country"]  = r.get("country", "N/A")
        data["location"] = r.get("loc", "N/A")
        data["org"]      = r.get("org", "N/A")
        data["timezone"] = r.get("timezone", "N/A")
        if data["location"] and data["location"] != "N/A":
            data["google_maps"] = f"https://maps.google.com/?q={data['location']}"
    except Exception as e:
        data["ipinfo_error"] = str(e)

    _print_table("IP Lookup", data)
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
