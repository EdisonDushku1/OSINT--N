"""
OSINT--N | Module: Phone Number Lookup
"""

import os
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def run(target: str, config: dict) -> dict:
    console.rule(f"[bold cyan] PHONE LOOKUP — {target}")
    data = {"module": "phone", "target": target}

    try:
        parsed = phonenumbers.parse(target, None)
        data["valid"]        = phonenumbers.is_valid_number(parsed)
        data["possible"]     = phonenumbers.is_possible_number(parsed)
        data["country_code"] = parsed.country_code
        data["region"]       = phonenumbers.region_code_for_number(parsed)
        data["location"]     = geocoder.description_for_number(parsed, "en")
        data["carrier"]      = carrier.name_for_number(parsed, "en") or "N/A"
        data["timezones"]    = ", ".join(timezone.time_zones_for_number(parsed))
        data["number_type"]  = str(phonenumbers.number_type(parsed))
        data["e164"]         = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        data["international"]= phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        data["national"]     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    except Exception as e:
        data["parse_error"] = str(e)
        console.print(f"[red][!] Could not parse number: {e}[/red]")
        return data

    # NumVerify API
    nv_key = os.getenv("NUMVERIFY_API_KEY", "")
    if nv_key:
        try:
            r = requests.get(
                "http://apilayer.net/api/validate",
                params={"access_key": nv_key, "number": target, "format": 1},
                timeout=config["general"]["timeout_seconds"]
            ).json()
            data["numverify_valid"]    = r.get("valid", "N/A")
            data["numverify_line_type"]= r.get("line_type", "N/A")
            data["numverify_carrier"]  = r.get("carrier", "N/A")
            data["numverify_location"] = r.get("location", "N/A")
        except Exception as e:
            data["numverify_error"] = str(e)
    else:
        data["numverify"] = "No API key"

    _print_table("Phone Lookup", data)
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
