"""
OSINT--N | Module: Image Metadata / EXIF Extractor
"""

import os
import requests
import tempfile
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def run(target: str, config: dict) -> dict:
    """
    target: path to a local image file OR a remote image URL
    """
    console.rule(f"[bold cyan] METADATA EXTRACTOR — {target}")
    data = {"module": "metadata", "target": target}

    try:
        import exifread
        from PIL import Image
    except ImportError:
        console.print("[red][!] Missing: pip install exifread Pillow[/red]")
        return data

    # Download if URL
    file_path = target
    tmp = None
    if target.startswith("http://") or target.startswith("https://"):
        try:
            r = requests.get(target, timeout=config["general"]["timeout_seconds"])
            suffix = Path(target).suffix or ".jpg"
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            tmp.write(r.content)
            tmp.close()
            file_path = tmp.name
            data["source"] = "remote"
        except Exception as e:
            data["download_error"] = str(e)
            return data
    else:
        data["source"] = "local"

    if not os.path.exists(file_path):
        console.print(f"[red][!] File not found: {file_path}[/red]")
        return data

    # PIL basic info
    try:
        img = Image.open(file_path)
        data["format"]     = img.format
        data["mode"]       = img.mode
        data["dimensions"] = f"{img.width} x {img.height} px"
        data["file_size"]  = f"{os.path.getsize(file_path):,} bytes"
    except Exception as e:
        data["pil_error"] = str(e)

    # EXIF data
    try:
        with open(file_path, "rb") as f:
            tags = exifread.process_file(f, stop_tag="UNDEF", details=True)

        interesting = [
            "GPS GPSLatitude", "GPS GPSLongitude", "GPS GPSAltitude",
            "GPS GPSLatitudeRef", "GPS GPSLongitudeRef",
            "Image Make", "Image Model", "Image Software",
            "Image DateTime", "Image Artist", "Image Copyright",
            "EXIF DateTimeOriginal", "EXIF DateTimeDigitized",
            "EXIF ExifImageWidth", "EXIF ExifImageLength",
            "EXIF Flash", "EXIF FocalLength", "EXIF ISOSpeedRatings",
        ]

        for tag in interesting:
            if tag in tags:
                data[tag.replace(" ", "_")] = str(tags[tag])

        # GPS coords → decimal
        if "GPS GPSLatitude" in tags and "GPS GPSLongitude" in tags:
            try:
                lat  = _dms_to_decimal(tags["GPS GPSLatitude"].values,
                                       str(tags.get("GPS GPSLatitudeRef", "N")))
                lon  = _dms_to_decimal(tags["GPS GPSLongitude"].values,
                                       str(tags.get("GPS GPSLongitudeRef", "E")))
                data["gps_decimal"]  = f"{lat:.6f}, {lon:.6f}"
                data["google_maps"]  = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
                console.print(f"\n  [bold green][!] GPS FOUND → {data['gps_decimal']}[/bold green]")
                console.print(f"  [bold green]    Google Maps: {data['google_maps']}[/bold green]\n")
            except:
                pass

        data["total_exif_tags"] = len(tags)

    except Exception as e:
        data["exif_error"] = str(e)

    # Cleanup temp file
    if tmp:
        try:
            os.unlink(tmp.name)
        except:
            pass

    _print_table("Image Metadata", data)
    return data


def _dms_to_decimal(dms_values, ref: str) -> float:
    d = float(dms_values[0].num) / float(dms_values[0].den)
    m = float(dms_values[1].num) / float(dms_values[1].den)
    s = float(dms_values[2].num) / float(dms_values[2].den)
    result = d + (m / 60.0) + (s / 3600.0)
    if ref in ("S", "W"):
        result = -result
    return result


def _print_table(title, data):
    t = Table(title=title, box=box.ROUNDED, border_style="cyan", title_style="bold cyan")
    t.add_column("Field", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in data.items():
        if k == "module":
            continue
        t.add_row(str(k), str(v) if v else "[dim]N/A[/dim]")
    console.print(t)
