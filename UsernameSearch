"""
OSINT--N | Module: Username Search (Async)
"""

import asyncio
import httpx
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

PLATFORMS = {
    "GitHub":      "https://github.com/{}",
    "Twitter":     "https://twitter.com/{}",
    "Instagram":   "https://www.instagram.com/{}/",
    "Reddit":      "https://www.reddit.com/user/{}",
    "TikTok":      "https://www.tiktok.com/@{}",
    "Pinterest":   "https://www.pinterest.com/{}/",
    "Twitch":      "https://www.twitch.tv/{}",
    "YouTube":     "https://www.youtube.com/@{}",
    "Telegram":    "https://t.me/{}",
    "Snapchat":    "https://www.snapchat.com/add/{}",
    "SoundCloud":  "https://soundcloud.com/{}",
    "Spotify":     "https://open.spotify.com/user/{}",
    "Pastebin":    "https://pastebin.com/u/{}",
    "Keybase":     "https://keybase.io/{}",
    "GitLab":      "https://gitlab.com/{}",
    "Medium":      "https://medium.com/@{}",
    "Dev.to":      "https://dev.to/{}",
    "Hackerone":   "https://hackerone.com/{}",
    "Bugcrowd":    "https://bugcrowd.com/{}",
    "ProductHunt": "https://www.producthunt.com/@{}",
}

NOT_FOUND_INDICATORS = [
    "not found", "doesn't exist", "no results",
    "page not found", "404", "user not found",
    "this account doesn't exist", "sorry, this page isn't available"
]

async def check_platform(client: httpx.AsyncClient, platform: str, url: str, username: str) -> dict:
    try:
        r = await client.get(url, timeout=10, follow_redirects=True)
        body = r.text.lower()
        found = r.status_code == 200 and not any(x in body for x in NOT_FOUND_INDICATORS)
        return {"platform": platform, "url": url, "status": r.status_code, "found": found}
    except Exception as e:
        return {"platform": platform, "url": url, "status": "error", "found": False}

async def _run_async(username: str) -> list:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    results = []
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        tasks = [
            check_platform(client, platform, url.format(username), username)
            for platform, url in PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks)
    return results

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] USERNAME SEARCH — {target}")
    data = {"module": "username", "target": target}

    results = asyncio.run(_run_async(target))

    t = Table(title=f"Username: {target}", box=box.ROUNDED,
              border_style="cyan", title_style="bold cyan")
    t.add_column("Platform",  style="bold yellow", no_wrap=True)
    t.add_column("Status",    style="bold", justify="center")
    t.add_column("URL",       style="dim")

    found_list = []
    for res in sorted(results, key=lambda x: x["platform"]):
        if res["found"]:
            found_list.append(res["platform"])
            t.add_row(res["platform"], "[green]✔ FOUND[/green]", res["url"])
            data[f"{res['platform'].lower()}_url"] = res["url"]
        else:
            status_str = str(res["status"])
            t.add_row(res["platform"], f"[red]✘ {status_str}[/red]", res["url"])

    console.print(t)
    data["found_count"]     = len(found_list)
    data["found_platforms"] = ", ".join(found_list)
    console.print(f"\n  [green]Found on {len(found_list)} platform(s)[/green] out of {len(PLATFORMS)} checked.\n")
    return data
