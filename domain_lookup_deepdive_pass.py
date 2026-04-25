#!/usr/bin/env python3
"""
Third-pass domain analysis: origin detection for proxy-obscured sites.

For rows where HOSTING_PROVIDER is Cloudflare (or other WAF/proxy), attempts to
identify the real origin host using two signals Cloudflare can't hide:

  1. Unproxied subdomains — cpanel., ftp., dev., staging. etc. frequently bypass
     Cloudflare and reveal the origin host. Email subdomains (mail., smtp.) are
     intentionally excluded: they reflect email infrastructure, not web hosting,
     and are commonly left pointing at old providers long after migration.
  2. Certificate Transparency logs (crt.sh) — historical certs may include
     provider-specific SANs (especially useful for Platform.sh / Upsun)

DKIM records are collected as raw signals for inspection but are NOT used to
classify HOSTING_PROVIDER — DKIM is email signing infrastructure and says nothing
reliable about where the web server lives.

Rewrites HOSTING_PROVIDER in place for any rows where a signal is found.

Usage:
    python3 domain_lookup_deepdive_pass.py --file results.csv [--platform Magento]
"""
from __future__ import annotations

import argparse
import csv
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PROVIDER_PATTERNS: dict[str, list[str]] = {
    "Webscale":              ["webscale.com", "webscaledns.com"],
    "JetRails":              ["jetrails.com"],
    "Platform.sh":           ["platform.sh", "platformsh.site"],
    "Upsun":                 ["upsun.com"],
    "Cloudways":             ["cloudways.com"],
    "Nexcess / Liquid Web":  ["nexcess.net", "liquidweb.com", "lwmark.com"],
    "WP Engine":             ["wpengine.com"],
    "Kinsta":                ["kinsta.cloud", "kinstahosting"],
    "SiteGround":            ["siteground.net", "sgcpanel"],
    "Rackspace":             ["rackspace.com"],
    "Pagely":                ["pagely.com"],
    "Pressidium":            ["pressidium.com"],
}

PROXY_KEYWORDS   = ("cloudflare", "sucuri", "wix", "squarespace", "sedo")
DKIM_SELECTORS   = ["default", "google", "dkim", "mail", "k1", "k2", "s1", "s2", "mx", "smtp"]
PROBE_SUBDOMAINS = ["cpanel", "ftp", "dev", "staging", "m"]

MAX_WORKERS = 10   # crt.sh rate-limits; DNS checks are fast within this pool


def _dig(record_type: str, name: str) -> str:
    try:
        r = subprocess.run(
            ["dig", "+short", record_type, name],
            capture_output=True, text=True, timeout=8
        )
        return r.stdout.lower()
    except Exception:
        return ""


def _match(text: str) -> str | None:
    for provider, patterns in PROVIDER_PATTERNS.items():
        if any(p in text for p in patterns):
            return provider
    return None


def check_dkim(domain: str) -> tuple[str | None, str, str]:
    """Returns (matched_provider, evidence, raw_signal)."""
    for selector in DKIM_SELECTORS:
        txt = _dig("TXT", f"{selector}._domainkey.{domain}")
        if txt.strip():
            p = _match(txt)
            raw = txt.strip()[:100]
            if p:
                return p, f"DKIM {selector}._domainkey: {raw}", raw
            return None, "", raw
    return None, "", ""


def check_subdomains(domain: str) -> tuple[str | None, str, str]:
    """Returns (matched_provider, evidence, raw_signal)."""
    best_raw = ""
    for sub in PROBE_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            try:
                rdns = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                rdns = ip
            if "cloudflare" in rdns:
                continue
            p = _match(rdns)
            raw = f"{fqdn} → {rdns or ip}"
            if p:
                return p, raw, raw
            if not best_raw:
                best_raw = raw
        except socket.gaierror:
            continue
    return None, "", best_raw


def check_ct_logs(domain: str, session: requests.Session) -> tuple[str | None, str, str]:
    """Returns (matched_provider, evidence, raw_signal)."""
    try:
        resp = session.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=20,
        )
        if resp.status_code != 200:
            return None, "", ""
        for cert in resp.json()[:50]:
            combined = (
                (cert.get("name_value") or "") + " " +
                (cert.get("common_name") or "")
            ).lower()
            # Skip trivially generic entries
            if combined.strip() in ("", domain.lower()):
                continue
            p = _match(combined)
            # Extract non-trivial SANs (not just the customer domain itself)
            sans = [
                s.strip() for s in combined.split()
                if s.strip() and domain not in s and "*." not in s
                and len(s.strip()) > 4
            ]
            raw = " | ".join(sans[:3]) if sans else ""
            if p:
                return p, f"CT log SAN: {raw}", raw
            if raw:
                return None, "", raw
    except Exception:
        pass
    return None, "", ""


def check_domain(domain: str, session: requests.Session) -> dict:
    result: dict = {
        "domain": domain, "provider": None, "method": "", "evidence": "",
        "raw_dkim": "", "raw_subdomain": "", "raw_ct": "",
    }

    # DKIM reflects email infrastructure only — collected for inspection but never
    # used to classify web hosting provider.
    _, _, raw = check_dkim(domain)
    result["raw_dkim"] = raw

    p, ev, raw = check_subdomains(domain)
    result["raw_subdomain"] = raw
    if p:
        result.update({"provider": p, "method": "subdomain", "evidence": ev})
        return result

    p, ev, raw = check_ct_logs(domain, session)
    result["raw_ct"] = raw
    if p:
        result.update({"provider": p, "method": "CT log", "evidence": ev})

    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", required=True)
    parser.add_argument("--platform", default="Magento",
                        help="Only check rows with this PLATFORM value (default: Magento)")
    args = parser.parse_args()

    csv_path = Path(args.file).expanduser()
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))

    targets = [
        (i, r) for i, r in enumerate(rows)
        if r.get("PLATFORM") == args.platform
        and any(kw in (r.get("HOSTING_PROVIDER") or "").lower() for kw in PROXY_KEYWORDS)
        and r.get("DOMAIN_CHECKED")
    ]
    print(f"{len(targets)} {args.platform} domains behind proxy. Running subdomain and CT log checks...")

    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.5)))
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )

    hits: list[dict] = []
    all_results: list[dict] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(check_domain, r["DOMAIN_CHECKED"], session): (i, r)
            for i, r in targets
        }
        for future in as_completed(future_map):
            i, _row = future_map[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"domain": _row["DOMAIN_CHECKED"], "provider": None,
                          "method": "", "evidence": str(e),
                          "raw_dkim": "", "raw_subdomain": "", "raw_ct": ""}

            all_results.append(result)
            if result["provider"]:
                rows[i]["HOSTING_PROVIDER"] = result["provider"]
                hits.append(result)

            completed += 1
            if completed % 25 == 0 or completed == len(targets):
                print(f"  {completed}/{len(targets)}...")

    print(f"\nResolved {len(hits)} of {len(targets)} proxied domains.")

    if hits:
        print("\nKnown provider matches:")
        for h in sorted(hits, key=lambda x: x["provider"]):
            print(f"  {h['provider']:<22} via {h['method']:<10}  {h['domain']}")
            if h["evidence"]:
                print(f"  {'':22}      {h['evidence'][:100]}")

        fieldnames = list(rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nCSV updated: {csv_path}")

    # Print raw signals for unmatched domains
    raw_signals = [
        r for r in all_results
        if not r["provider"] and (r["raw_dkim"] or r["raw_subdomain"] or r["raw_ct"])
    ]
    if raw_signals:
        print(f"\nRaw signals from {len(raw_signals)} unmatched domains:")
        print(f"{'Domain':<35} {'Source':<10} Signal")
        print("-" * 90)
        for r in sorted(raw_signals, key=lambda x: x["domain"]):
            for src, key in [("subdomain", "raw_subdomain"), ("DKIM", "raw_dkim"), ("CT", "raw_ct")]:
                val = r.get(key, "")
                if val:
                    print(f"  {r['domain']:<33} {src:<10} {val[:60]}")
    else:
        print("\nNo raw signals found either — these domains are clean behind Cloudflare.")


if __name__ == "__main__":
    main()
