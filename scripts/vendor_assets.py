"""Download Bootstrap and Chart.js into siem/static/vendor/ so the dashboard works offline.

Run once while you have internet access:

    python scripts/vendor_assets.py

The templates automatically prefer these local copies over the CDN.
"""
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from siem.web.views import VENDOR_ASSETS  # noqa: E402

VENDOR_DIR = ROOT / "siem" / "static" / "vendor"


def main():
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    for name, (filename, url) in VENDOR_ASSETS.items():
        target = VENDOR_DIR / filename
        print(f"Downloading {name}: {url}")
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 (fixed HTTPS URLs)
            target.write_bytes(response.read())
        print(f"  saved {target.relative_to(ROOT)} ({target.stat().st_size // 1024} KB)")
    print("Done. Restart the app if it is running.")


if __name__ == "__main__":
    main()
