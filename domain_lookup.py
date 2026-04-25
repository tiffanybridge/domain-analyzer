#!/usr/bin/env python3
"""
Domain hosting and platform analysis for churned services.

For each service row in a CSV, checks whether the domain still resolves,
what platform currently powers it, and what hosting provider it's on.

Usage:
    pip install requests ipwhois
    python3 domain_lookup.py --input ~/Downloads/services.csv --output results.csv

    # Skip internal staging domains:
    python3 domain_lookup.py --input services.csv --output results.csv --skip-suffix .staging.example.com

Output columns added: DOMAIN_CHECKED, DNS_RESOLVES, HTTP_STATUS, FINAL_URL,
                      PLATFORM, HOSTING_PROVIDER, CONFIDENCE, BUILTWITH_FOLLOWUP
"""
from __future__ import annotations

import argparse
import csv
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print("Warning: ipwhois not installed. ASN-based hosting detection disabled.")
    print("Run: pip install ipwhois\n")

def _parse_args() -> tuple[Path, Path, tuple[str, ...]]:
    parser = argparse.ArgumentParser(description="Analyze domains from a churned-services CSV.")
    parser.add_argument("--input",  "-i", required=True, help="Path to input CSV file")
    parser.add_argument("--output", "-o", required=True, help="Path for enriched output CSV")
    parser.add_argument(
        "--skip-suffix", default="",
        help="Comma-separated domain suffixes to skip (e.g. .nxcli.net,.nxcli.io for Nexcess staging)"
    )
    args = parser.parse_args()
    suffixes = tuple(s.strip() for s in args.skip_suffix.split(",") if s.strip())
    return Path(args.input).expanduser(), Path(args.output).expanduser(), suffixes

MAX_WORKERS = 25
REQUEST_TIMEOUT = 10
MAX_CONTENT_BYTES = 150_000

# Set in main() after arg parsing — domains ending in these suffixes are skipped
TEMP_SUFFIXES: tuple[str, ...] = ()

# Thread-safe cache for IP -> hosting info (avoids duplicate WHOIS queries)
_ip_cache: dict[str, str] = {}
_ip_cache_lock = threading.Lock()

# Ordered list: first match wins. Each entry is:
#   (platform_name, confidence, [(check_type, pattern), ...])
# check_type: "html" | "header_key" | "header_val" | "cookie" | "url"
PLATFORM_RULES: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("Shopify", "high", [
        ("html",       "cdn.shopify.com"),
        ("html",       "shopify.theme"),
        ("html",       "myshopify.com"),
        ("cookie",     "__shopify_y"),
        ("header_key", "x-shopify"),
    ]),
    ("BigCommerce", "high", [
        ("html",       "bigcommerce.com"),
        ("header_key", "x-bc-csp"),
        ("cookie",     "bcsession"),
    ]),
    ("WooCommerce", "high", [
        ("html", "wp-content/plugins/woocommerce"),
    ]),
    ("Shopware", "high", [
        ("html",       "/bundles/storefront/"),
        ("html",       "sw-storefront"),
        ("html",       '"shopware"'),
        ("cookie",     "shopware"),
        ("header_val", "shopware"),
    ]),
    ("Salesforce Commerce Cloud", "high", [
        ("html", "demandware.static"),
        ("html", "demandware.net"),
    ]),
    ("PrestaShop", "high", [
        ("html", "prestashop"),
    ]),
    ("Magento", "high", [
        ("html", 'data-mage-'),
        ("html", "magento_"),
        ("html", "/static/version"),   # Magento static asset URLs
        ("html", "mage/"),
    ]),
    ("Squarespace", "high", [
        ("html", "static1.squarespace.com"),
    ]),
    ("Wix", "high", [
        ("html",       "parastorage.com"),   # Wix media CDN
        ("html",       "_wixcssmodules"),
        ("header_key", "x-wix-"),
    ]),
    ("Webflow", "high", [
        ("html", "webflow.com"),
        ("html", 'generator" content="webflow'),
    ]),
    ("WordPress", "medium", [
        ("html", "wp-content/"),
        ("html", "wp-includes/"),
    ]),
]

# Ordered list for hosting detection:
#   (provider_name, [(check_type, pattern), ...])
# check_type: "rdns" | "header_key" | "header_val"
HOSTING_RULES: list[tuple[str, list[tuple[str, str]]]] = [
    ("Shopify",            [("rdns", "shopify.com"), ("html", "myshopify.com")]),
    ("WP Engine",          [("rdns", "wpengine.com"), ("header_val", "wp engine")]),
    ("Kinsta",             [("rdns", "kinsta.cloud"), ("rdns", "kinstahosting")]),
    ("Nexcess / Liquid Web", [("rdns", "nexcess.net"), ("rdns", "liquidweb.com"), ("rdns", "lwmark.com")]),
    ("Vercel",             [("rdns", "vercel.com"), ("header_key", "x-vercel-id")]),
    ("Netlify",            [("rdns", "netlify.com"), ("header_key", "x-netlify")]),
    ("Pantheon",           [("rdns", "pantheonsite.io"), ("header_val", "pantheon")]),
    ("Flywheel",           [("rdns", "flywheel.com")]),
    ("SiteGround",         [("rdns", "siteground.net"), ("rdns", "sgcpanel")]),
    ("GoDaddy",            [("rdns", "secureserver.net")]),
    ("Cloudflare",         [("header_key", "cf-ray"), ("header_val", "cloudflare")]),
    ("Webscale",          [("rdns", "webscale.com"), ("rdns", "webscaledns.com"),
                           ("header_key", "x-webscale-request-id"), ("header_key", "x-webscale-cache"),
                           ("html", "cdn.webscale.com")]),
    ("JetRails",          [("rdns", "jetrails.com"), ("header_key", "x-jetrails")]),
    ("Platform.sh",       [("rdns", "platform.sh"), ("rdns", "platformsh.site"),
                           ("header_key", "x-platform-cache"), ("header_key", "x-platform-cluster"),
                           ("header_key", "x-platform-branch")]),
    ("Upsun",             [("rdns", "upsun.com"), ("header_key", "x-upsun-request-id")]),
    ("AWS",                [("rdns", "amazonaws.com"), ("rdns", "awsglobalaccelerator.com")]),
    ("Google Cloud",       [("rdns", "1e100.net")]),
    ("Fastly",             [("rdns", "fastly.net"), ("header_key", "x-fastly-request-id")]),
    ("Azure",              [("rdns", "cloudapp.azure.com"), ("rdns", "azurewebsites.net")]),
]

ASN_HOSTING_MAP = {
    "shopify":     "Shopify",
    "automattic":  "WordPress.com",
    "amazon":      "AWS",
    "google":      "Google Cloud",
    "microsoft":   "Azure",
    "cloudflare":  "Cloudflare",
    "liquid web":  "Nexcess / Liquid Web",
    "nexcess":     "Nexcess / Liquid Web",
    "wpengine":    "WP Engine",
    "fastly":      "Fastly",
    "netlify":     "Netlify",
    "vercel":      "Vercel",
    "webscale":    "Webscale",
    "jetrails":    "JetRails",
}


def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
    return session


def is_temp_domain(domain: str) -> bool:
    return any(domain.lower().endswith(s) for s in TEMP_SUFFIXES)


def pick_domain(row: dict) -> str | None:
    """Return the best real domain for this row, or None if none available."""
    for col in ("PRIMARY_DOMAIN", "SITE_DOMAIN", "CLIENT_DOMAIN"):
        val = (row.get(col) or "").strip().lower()
        if val and not is_temp_domain(val):
            # Strip www. prefix so we can try with and without
            if val.startswith("www."):
                val = val[4:]
            return val
    return None


def resolve_ip(domain: str) -> str | None:
    """Return the IP address for a domain, trying bare and www. variants."""
    for candidate in (domain, f"www.{domain}"):
        try:
            return socket.gethostbyname(candidate)
        except socket.gaierror:
            continue
    return None


def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""


def asn_description(ip: str) -> str:
    if not IPWHOIS_AVAILABLE:
        return ""
    with _ip_cache_lock:
        if ip in _ip_cache:
            return _ip_cache[ip]
    try:
        result = IPWhois(ip).lookup_rdap(depth=0)
        desc = (result.get("asn_description") or "").lower()
    except Exception:
        desc = ""
    with _ip_cache_lock:
        _ip_cache[ip] = desc
    return desc


def detect_platform(headers: dict, html_lower: str, cookie_keys: str) -> tuple[str, str]:
    h = {k.lower(): v.lower() for k, v in headers.items()}
    for platform, confidence, rules in PLATFORM_RULES:
        for check_type, pattern in rules:
            pat = pattern.lower()
            matched = False
            if check_type == "html":
                matched = pat in html_lower
            elif check_type == "header_key":
                matched = any(pat in k for k in h)
            elif check_type == "header_val":
                matched = any(pat in v for v in h.values())
            elif check_type == "cookie":
                matched = pat in cookie_keys
            if matched:
                return platform, confidence
    return "Unknown", "low"


def detect_hosting(headers: dict, reverse_dns: str, ip: str) -> str:
    h = {k.lower(): v.lower() for k, v in headers.items()}
    for provider, rules in HOSTING_RULES:
        for check_type, pattern in rules:
            pat = pattern.lower()
            matched = False
            if check_type == "rdns":
                matched = pat in reverse_dns
            elif check_type == "header_key":
                matched = any(pat in k for k in h)
            elif check_type == "header_val":
                matched = any(pat in v for v in h.values())
            if matched:
                return provider
    # Fall back to ASN lookup
    asn = asn_description(ip)
    for keyword, provider in ASN_HOSTING_MAP.items():
        if keyword in asn:
            return provider
    if asn:
        # Return first 60 chars of raw ASN description for unknown providers
        return asn[:60].title()
    return "Unknown"


def check_row(row: dict) -> dict:
    result = dict(row)
    result.update({
        "DOMAIN_CHECKED":    "",
        "DNS_RESOLVES":      "no",
        "HTTP_STATUS":       "",
        "FINAL_URL":         "",
        "PLATFORM":          "",
        "HOSTING_PROVIDER":  "",
        "CONFIDENCE":        "",
        "BUILTWITH_FOLLOWUP": "no",
    })

    domain = pick_domain(row)
    if not domain:
        result["PLATFORM"] = "NO_REAL_DOMAIN"
        return result

    result["DOMAIN_CHECKED"] = domain
    ip = resolve_ip(domain)
    if not ip:
        result["DNS_RESOLVES"] = "no"
        return result

    result["DNS_RESOLVES"] = "yes"
    session = make_session()
    resp = None
    html = ""

    for scheme in ("https", "http"):
        try:
            r = session.get(
                f"{scheme}://{domain}",
                timeout=REQUEST_TIMEOUT,
                stream=True,
                allow_redirects=True,
            )
            # Read up to MAX_CONTENT_BYTES, then close the stream
            chunks = []
            total = 0
            for chunk in r.iter_content(chunk_size=8192):
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_CONTENT_BYTES:
                    break
            r.close()
            html = b"".join(chunks).decode("utf-8", errors="ignore")
            resp = r
            break
        except Exception:
            continue

    if resp is None:
        result["HTTP_STATUS"] = "timeout/error"
        result["PLATFORM"] = "No Response"
        result["BUILTWITH_FOLLOWUP"] = "yes"
        return result

    result["HTTP_STATUS"] = str(resp.status_code)
    result["FINAL_URL"] = resp.url

    cookie_keys = " ".join(resp.cookies.keys()).lower()
    platform, confidence = detect_platform(resp.headers, html.lower(), cookie_keys)
    reverse_dns = rdns(ip)
    hosting = detect_hosting(resp.headers, reverse_dns, ip)

    result["PLATFORM"] = platform
    result["HOSTING_PROVIDER"] = hosting
    result["CONFIDENCE"] = confidence
    result["BUILTWITH_FOLLOWUP"] = "yes" if platform == "Unknown" and result["DNS_RESOLVES"] == "yes" else "no"

    return result


def main() -> None:
    global TEMP_SUFFIXES
    input_file, output_file, TEMP_SUFFIXES = _parse_args()

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    with open(input_file, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"Loaded {len(rows)} rows from {input_file.name}")
    if TEMP_SUFFIXES:
        print(f"Skipping domains ending in: {', '.join(TEMP_SUFFIXES)}")
    print(f"Running with {MAX_WORKERS} concurrent workers...\n")

    # Attach original index so we can restore row order after concurrent processing
    indexed = [(i, row) for i, row in enumerate(rows)]
    results: list[tuple[int, dict]] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {executor.submit(check_row, row): i for i, row in indexed}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results.append((idx, future.result()))
            except Exception as e:
                original = indexed[idx][1]
                results.append((idx, {**original, "HTTP_STATUS": f"ERROR: {e}",
                                       "PLATFORM": "ERROR", "DNS_RESOLVES": "no",
                                       "DOMAIN_CHECKED": "", "FINAL_URL": "",
                                       "HOSTING_PROVIDER": "", "CONFIDENCE": "",
                                       "BUILTWITH_FOLLOWUP": "no"}))
            completed += 1
            if completed % 50 == 0 or completed == len(rows):
                print(f"  {completed}/{len(rows)} processed...")

    # Restore original CSV row order
    results.sort(key=lambda x: x[0])
    output_rows = [r for _, r in results]

    fieldnames = list(rows[0].keys()) + [
        "DOMAIN_CHECKED", "DNS_RESOLVES", "HTTP_STATUS", "FINAL_URL",
        "PLATFORM", "HOSTING_PROVIDER", "CONFIDENCE", "BUILTWITH_FOLLOWUP",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"\nOutput written to: {output_file}\n")

    # Summary
    platforms: dict[str, int] = {}
    for r in output_rows:
        p = r.get("PLATFORM", "") or ""
        platforms[p] = platforms.get(p, 0) + 1

    print("Platform breakdown:")
    for p, count in sorted(platforms.items(), key=lambda x: -x[1]):
        pct = count / len(output_rows) * 100
        print(f"  {p or '(blank)':<35} {count:>4}  ({pct:.1f}%)")

    followup = sum(1 for r in output_rows if r.get("BUILTWITH_FOLLOWUP") == "yes")
    no_domain = sum(1 for r in output_rows if r.get("PLATFORM") == "NO_REAL_DOMAIN")
    dns_down  = sum(1 for r in output_rows if r.get("DNS_RESOLVES") == "no" and r.get("PLATFORM") != "NO_REAL_DOMAIN")
    print(f"\n  No real domain (temp/blank only): {no_domain}")
    print(f"  Domain no longer resolves (gone): {dns_down}")
    print(f"  Flagged for BuiltWith follow-up:  {followup}")


if __name__ == "__main__":
    main()
