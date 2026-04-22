#!/usr/bin/env python3
"""
Second-pass domain analysis using Wappalyzer technology definitions.

Reads the output of domain_lookup.py, finds rows where BUILTWITH_FOLLOWUP=yes
(live sites with undetected platform), fetches fresh Wappalyzer signatures from
GitHub, applies them, and writes an updated CSV in-place.

Usage:
    python3 domain_lookup_wappalyzer_pass.py --file results.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def _parse_args() -> Path:
    parser = argparse.ArgumentParser(description="Wappalyzer second-pass for undetected domains.")
    parser.add_argument("--file", "-f", required=True, help="Path to the enriched CSV (edited in place)")
    return Path(parser.parse_args().file).expanduser()

# Wappalyzer tech definitions — only fetch letters where our target platforms live
# b=BigCommerce, m=Magento, o=OpenCart, p=PrestaShop, s=Shopify/Shopware/Squarespace/Salesforce,
# v=Volusion, w=WooCommerce/WordPress/Webflow/Wix, 3=3dcart/Shift4Shop
WAPPALYZER_BASE = (
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{letter}.json"
)
LETTERS_TO_FETCH = list("bcmopsvw") + ["_"]  # _ covers non-alpha starts

# Wappalyzer category IDs we care about
TARGET_CATEGORIES = {
    1:  "CMS",
    6:  "Ecommerce",
    11: "Blog",
    67: "Website builder",
    22: "Web hosting",
    87: "Hosted solution",
}

# Map Wappalyzer tech names to our canonical platform labels
PLATFORM_CANONICAL = {
    "shopify":                   "Shopify",
    "woocommerce":               "WooCommerce",
    "bigcommerce":               "BigCommerce",
    "shopware":                  "Shopware",
    "magento":                   "Magento",
    "squarespace":               "Squarespace",
    "wix":                       "Wix",
    "webflow":                   "Webflow",
    "wordpress":                 "WordPress",
    "prestashop":                "PrestaShop",
    "opencart":                  "OpenCart",
    "volusion":                  "Volusion",
    "salesforce commerce cloud": "Salesforce Commerce Cloud",
    "demandware":                "Salesforce Commerce Cloud",
    "3dcart":                    "Shift4Shop",
    "shift4shop":                "Shift4Shop",
}

# Platforms to ignore (not ecommerce/CMS — hosting infra etc.)
IGNORE_TECH = {"jquery", "google analytics", "cloudflare", "google tag manager",
               "font awesome", "bootstrap", "google fonts"}

MAX_WORKERS = 15
REQUEST_TIMEOUT = 12
MAX_CONTENT_BYTES = 150_000

_tech_db: dict[str, dict] = {}  # name -> tech definition
_tech_db_lock = threading.Lock()


def make_session() -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.3))
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
    return s


def load_wappalyzer_db(session: requests.Session) -> None:
    """Download and cache Wappalyzer technology definitions."""
    cache_file = Path(__file__).parent / ".wappalyzer_cache.json"

    if cache_file.exists():
        print("  Loading Wappalyzer definitions from local cache...")
        with open(cache_file) as f:
            _tech_db.update(json.load(f))
        print(f"  {len(_tech_db)} technologies loaded.")
        return

    print("  Downloading Wappalyzer technology definitions from GitHub...")
    all_techs: dict[str, dict] = {}
    for letter in LETTERS_TO_FETCH:
        url = WAPPALYZER_BASE.format(letter=letter)
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                all_techs.update(data)
        except Exception as e:
            print(f"    Warning: could not fetch {letter}.json — {e}")

    print(f"  {len(all_techs)} technologies downloaded. Caching locally...")
    with open(cache_file, "w") as f:
        json.dump(all_techs, f)
    _tech_db.update(all_techs)


def clean_pattern(raw: str) -> str:
    """Strip Wappalyzer metadata suffixes like \\;version:\\1 from regex patterns."""
    return raw.split("\\;")[0]


def patterns_to_list(value) -> list[str]:
    """Normalize a Wappalyzer pattern value to a list of cleaned regex strings."""
    if not value:
        return []
    items = value if isinstance(value, list) else [value]
    return [clean_pattern(str(p)) for p in items if p]


def apply_tech(tech: dict, html: str, headers: dict, cookies: dict, url: str) -> bool:
    """Return True if any Wappalyzer pattern for this tech matches the response."""
    h_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower()

    # HTML body patterns
    for pat in patterns_to_list(tech.get("html")):
        try:
            if pat and re.search(pat, html, re.IGNORECASE):
                return True
        except re.error:
            pass

    # <script src=""> patterns (Wappalyzer field: scriptSrc)
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    # Also check Link header preload hints which often contain script URLs
    link_header = headers.get("link", headers.get("Link", ""))
    script_src_text = " ".join(script_srcs) + " " + link_header
    for pat in patterns_to_list(tech.get("scriptSrc") or tech.get("scripts")):
        try:
            if pat and re.search(pat, script_src_text, re.IGNORECASE):
                return True
        except re.error:
            pass

    # JS global variable patterns (check as text in HTML)
    if "js" in tech:
        for js_var in tech["js"]:
            if js_var.lower() in html_lower:
                return True

    # URL patterns
    for pat in patterns_to_list(tech.get("url")):
        try:
            if pat and re.search(pat, url, re.IGNORECASE):
                return True
        except re.error:
            pass

    # Header patterns: {"X-Powered-By": "WordPress"}
    if "headers" in tech:
        for header_name, header_pat in tech["headers"].items():
            hn = header_name.lower()
            if hn in h_lower:
                for pat in patterns_to_list(header_pat if header_pat else ""):
                    try:
                        if not pat or re.search(pat, h_lower[hn], re.IGNORECASE):
                            return True
                    except re.error:
                        pass
                # Empty pattern = header existence check
                if not header_pat:
                    return True

    # Cookie patterns: {"__shopify_y": ""}
    if "cookies" in tech:
        for cookie_name, cookie_pat in tech["cookies"].items():
            cn = cookie_name.lower()
            matching_cookies = {k.lower(): v for k, v in cookies.items()}
            if cn in matching_cookies:
                for pat in patterns_to_list(cookie_pat if cookie_pat else ""):
                    try:
                        if not pat or re.search(pat, matching_cookies[cn], re.IGNORECASE):
                            return True
                    except re.error:
                        pass
                if not cookie_pat:
                    return True

    # Meta tag patterns: {"generator": "WordPress"}
    if "meta" in tech:
        for meta_name, meta_pat in tech["meta"].items():
            meta_vals = re.findall(
                rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)',
                html, re.IGNORECASE
            )
            for val in meta_vals:
                for pat in patterns_to_list(meta_pat if meta_pat else ""):
                    try:
                        if not pat or re.search(pat, val, re.IGNORECASE):
                            return True
                    except re.error:
                        pass

    return False


ECOMMERCE_PRIORITY = [
    "shopify", "bigcommerce", "woocommerce", "shopware",
    "salesforce commerce cloud", "demandware", "prestashop",
    "opencart", "volusion", "3dcart", "shift4shop", "magento",
]
BUILDER_PRIORITY = ["squarespace", "wix", "webflow"]
CMS_PRIORITY = ["wordpress"]


def pick_best_platform(detected: list[str]) -> str | None:
    """Given a list of detected tech names (lowercased), return the best platform label."""
    detected_lower = [d.lower() for d in detected]
    for name in ECOMMERCE_PRIORITY + BUILDER_PRIORITY + CMS_PRIORITY:
        if name in detected_lower:
            return PLATFORM_CANONICAL.get(name, name.title())
    # Fall back to first detected tech that has a canonical mapping
    for name in detected_lower:
        if name in PLATFORM_CANONICAL:
            return PLATFORM_CANONICAL[name]
    return None


def detect_with_wappalyzer(html: str, headers: dict, cookies: dict, url: str) -> str | None:
    """Return best-matched platform name, or None if nothing matches."""
    detected = []
    for tech_name, tech_def in _tech_db.items():
        if tech_name.lower() in IGNORE_TECH:
            continue
        cats = tech_def.get("cats", [])
        if not any(c in TARGET_CATEGORIES for c in cats):
            continue
        if apply_tech(tech_def, html, headers, cookies, url):
            detected.append(tech_name)
    return pick_best_platform(detected)


def recheck_domain(domain: str) -> tuple[str, str, str]:
    """Return (platform, http_status, final_url) for a domain."""
    session = make_session()
    for scheme in ("https", "http"):
        try:
            r = session.get(
                f"{scheme}://{domain}",
                timeout=REQUEST_TIMEOUT,
                stream=True,
                allow_redirects=True,
            )
            chunks, total = [], 0
            for chunk in r.iter_content(8192):
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_CONTENT_BYTES:
                    break
            r.close()
            html = b"".join(chunks).decode("utf-8", errors="ignore")
            platform = detect_with_wappalyzer(html, dict(r.headers), dict(r.cookies), r.url)
            return platform or "Unknown", str(r.status_code), r.url
        except Exception:
            continue
    return "No Response", "timeout/error", ""


def main() -> None:
    input_output_file = _parse_args()

    if not input_output_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_output_file}")

    session = make_session()
    print("Step 1: Loading Wappalyzer technology database...")
    load_wappalyzer_db(session)

    print(f"\nStep 2: Reading {input_output_file.name}...")
    with open(input_output_file, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    flagged = [(i, r) for i, r in enumerate(rows) if r.get("BUILTWITH_FOLLOWUP") == "yes"]
    print(f"  {len(flagged)} rows flagged for follow-up.\n")

    if not flagged:
        print("Nothing to do — no rows flagged.")
        return

    print(f"Step 3: Re-checking {len(flagged)} domains with Wappalyzer matching...")
    updated = 0
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {
            executor.submit(recheck_domain, r["DOMAIN_CHECKED"]): (i, r)
            for i, r in flagged
            if r.get("DOMAIN_CHECKED")
        }
        for future in as_completed(future_to_idx):
            i, row = future_to_idx[future]
            try:
                platform, status, final_url = future.result()
            except Exception as e:
                platform, status, final_url = "Error", str(e), ""

            rows[i]["PLATFORM"] = platform
            rows[i]["HTTP_STATUS"] = status
            if final_url:
                rows[i]["FINAL_URL"] = final_url
            rows[i]["CONFIDENCE"] = "medium" if platform not in ("Unknown", "No Response", "Error") else "low"
            rows[i]["BUILTWITH_FOLLOWUP"] = "no" if platform not in ("Unknown", "No Response", "Error") else "yes"

            if platform not in ("Unknown", "No Response", "Error"):
                updated += 1

            completed += 1
            if completed % 20 == 0 or completed == len(flagged):
                print(f"  {completed}/{len(flagged)} done...")

    print(f"\nResolved {updated} of {len(flagged)} previously-unknown domains.")
    print(f"Writing updated CSV to {input_output_file}...")

    fieldnames = list(rows[0].keys())
    with open(input_output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Summary of newly detected platforms
    new_detections: dict[str, int] = {}
    resolved_rows = [rows[i] for i, _ in flagged]
    for r in resolved_rows:
        p = r.get("PLATFORM", "Unknown")
        new_detections[p] = new_detections.get(p, 0) + 1

    print("\nPlatform breakdown for previously-flagged domains:")
    for p, count in sorted(new_detections.items(), key=lambda x: -x[1]):
        print(f"  {p:<35} {count:>3}")

    still_unknown = sum(1 for r in resolved_rows if r.get("BUILTWITH_FOLLOWUP") == "yes")
    print(f"\nStill unresolved after Wappalyzer pass: {still_unknown}")
    if still_unknown > 0:
        print("  -> These are likely custom builds or sites behind WAFs. BuiltWith paid API is the next option.")


if __name__ == "__main__":
    main()
