"""
OSINT--N | Module: Subdomain Discovery
"""

import socket
import asyncio
import httpx
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

WORDLIST = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "forum", "admin", "portal", "api",
    "dev", "test", "staging", "app", "cdn", "media", "static", "assets",
    "beta", "demo", "old", "new", "wiki", "docs", "help", "support", "status",
    "dashboard", "login", "auth", "sso", "oauth", "git", "ci", "jenkins",
    "monitor", "metrics", "grafana", "jira", "confluence", "office", "email",
    "mx", "mx1", "mx2", "pop", "imap", "autodiscover", "cpanel", "whm",
    "phpmyadmin", "db", "database", "mysql", "postgres", "redis", "elastic",
    "s3", "files", "upload", "download", "images", "img", "assets", "backup"
]

async def check_subdomain(client: httpx.AsyncClient, fqdn: str) -> dict | None:
    try:
        ip = socket.gethostbyname(fqdn)
        try:
            r = await client.get(f"http://{fqdn}", timeout=5, follow_redirects=True)
            status = r.status_code
        except:
            status = "DNS only"
        return {"subdomain": fqdn, "ip": ip, "status": status}
    except:
        return None

async def _run_async(target: str) -> list:
    found = []
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient(headers=headers) as client:
        tasks = [
            check_subdomain(client, f"{sub}.{target}")
            for sub in WORDLIST
        ]
        results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] SUBDOMAIN DISCOVERY — {target}")
    data = {"module": "subdomain", "target": target}

    console.print(f"  [dim]Checking {len(WORDLIST)} subdomains asynchronously...[/dim]\n")
    found = asyncio.run(_run_async(target))

    t = Table(title=f"Subdomains of {target}", box=box.ROUNDED,
              border_style="cyan", title_style="bold cyan")
    t.add_column("Subdomain", style="bold yellow")
    t.add_column("IP",        style="white")
    t.add_column("HTTP",      style="cyan", justify="center")

    for entry in found:
        t.add_row(entry["subdomain"], entry["ip"], str(entry["status"]))

    console.print(t)
    console.print(f"\n  [green]{len(found)} subdomain(s) discovered.[/green]\n")

    data["count"]      = len(found)
    data["subdomains"] = ", ".join(e["subdomain"] for e in found)
    return data
