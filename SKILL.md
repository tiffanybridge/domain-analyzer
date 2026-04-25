---
name: domain-analysis
description: Analyze domains from a CSV of churned/canceled services — checks DNS resolution, detects hosting provider and ecommerce/CMS platform (Shopify, WooCommerce, BigCommerce, Shopware, Magento, etc.). Two-pass approach: HTTP fingerprinting first, Wappalyzer signatures second for undetected sites.
disable-model-invocation: false
user-invocable: true
---

# /domain-analysis - Domain Hosting & Platform Analysis

Given a CSV of canceled or churned services, this skill checks each domain to find out:
- Does the domain still resolve?
- What platform powers it now (Shopify, WooCommerce, BigCommerce, Shopware, Magento, etc.)?
- What hosting provider is it on?

## Quick Start

1. Tell me where your input CSV is (or I'll look in ~/Downloads for the most recent CSV)
2. I'll run the two-pass analysis — HTTP fingerprinting, then Wappalyzer for gaps
3. Output is an enriched CSV with PLATFORM, HOSTING_PROVIDER, CONFIDENCE, and BUILTWITH_FOLLOWUP columns added

**Example:** `/domain-analysis ~/Downloads/canceled_services_2026-05.csv`

**Output:** `outputs/analyses/domain-analysis-[date].csv`

**Runtime:** ~10-20 min for ~500 domains at 25 concurrent workers

---

## How It Works (Internal - for Claude)

### Scripts (already built, reuse these — do NOT rewrite them)
- **Pass 1:** `.claude/skills/domain-analysis/domain_lookup.py` — DNS resolution + HTTP fingerprinting via headers/HTML
- **Pass 2:** `.claude/skills/domain-analysis/domain_lookup_wappalyzer_pass.py` — Wappalyzer signatures for BUILTWITH_FOLLOWUP=yes rows
- **Pass 3 (optional):** `.claude/skills/domain-analysis/domain_lookup_deepdive_pass.py` — Origin detection for Cloudflare-proxied rows via unproxied subdomains (cpanel., ftp., dev., staging.) and Certificate Transparency logs. DKIM records are collected as raw signals but intentionally excluded from provider classification (email infrastructure, not web hosting). Run when you need to identify managed providers (Webscale, JetRails, Platform.sh, Upsun, etc.) hidden behind Cloudflare. Usage: `python3 domain_lookup_deepdive_pass.py --file results.csv --platform Magento`

Standalone users (running outside PM-OS) can run the scripts directly from the repo directory: `python3 domain_lookup.py --input ...`

### Step 1: Locate the input file
- If the user passed a path, use it directly
- Otherwise, find the most recently modified CSV in ~/Downloads:
  ```bash
  ls -t ~/Downloads/*.csv | head -1
  ```
- Show the user the filename and ask them to confirm before proceeding

### Step 2: Determine output filename
Format: `outputs/analyses/domain-analysis-YYYY-MM-DD.csv`
Use today's date. If a file with that name already exists, append `-2`, `-3`, etc.

### Step 3: Check dependencies
```bash
python3 -c "import requests, ipwhois" 2>&1
```
If missing:
```bash
pip install requests ipwhois
```

### Step 4: Ask about staging domain suffixes
Ask the user: "Do you have any internal staging domain suffixes to skip? These are temp domains that belong to your company, not customers — for example, `.nxcli.net,.nxcli.io` for Nexcess users. Leave blank to skip none."

- If they provide suffixes, pass them as `--skip-suffix "[their answer]"` in the next step
- If blank, omit the flag entirely

### Step 5: Run Pass 1
```bash
python3 .claude/skills/domain-analysis/domain_lookup.py \
  --input "[input_path]" \
  --output "[output_path]" \
  [--skip-suffix ".your-suffix.com,.another-suffix.com"]
```

**Expected input CSV columns** (at minimum one of these must be present and non-blank):
- `PRIMARY_DOMAIN`, `SITE_DOMAIN`, or `CLIENT_DOMAIN`

### Step 6: Run Pass 2 (Wappalyzer)
```bash
python3 .claude/skills/domain-analysis/domain_lookup_wappalyzer_pass.py \
  --file "[output_path]"
```

The Wappalyzer tech definitions are cached locally in `.claude/skills/domain-analysis/.wappalyzer_cache.json` after the first run. Delete that file to force a refresh.

### Step 7: Print summary
Show the platform breakdown from the output CSV:
```python
import csv
rows = list(csv.DictReader(open(output_path)))
# Count by PLATFORM, print sorted by count desc
```

---

## Output Columns Added

| Column | Values |
|---|---|
| `DOMAIN_CHECKED` | Which domain was queried |
| `DNS_RESOLVES` | yes / no |
| `HTTP_STATUS` | 200, 404, timeout/error, etc. |
| `FINAL_URL` | URL after redirects |
| `PLATFORM` | Shopify / WooCommerce / BigCommerce / Shopware / Magento / Squarespace / Wix / Webflow / WordPress / PrestaShop / OpenCart / Salesforce Commerce Cloud / Unknown / No Response / NO_REAL_DOMAIN |
| `HOSTING_PROVIDER` | Shopify / WP Engine / Kinsta / Nexcess / Vercel / Netlify / Cloudflare / AWS / etc. |
| `CONFIDENCE` | high / medium / low |
| `BUILTWITH_FOLLOWUP` | yes (live site, platform still unknown) / no |

---

## Interpreting Results

**NO_REAL_DOMAIN** — Row had only a staging/temp domain (from the skip list) or was blank. No customer domain to check.

**DNS dark / blank PLATFORM** — Domain doesn't resolve. Site is gone or domain expired.

**BUILTWITH_FOLLOWUP=yes** — Site is live but platform couldn't be fingerprinted. Likely a custom build or behind a WAF. BuiltWith paid API ($295/mo) is the next option for these.

**Still on original platform** — Customer migrated hosting but kept the same platform. A different retention problem than platform migration — worth segmenting separately.

---

## Limitations

- ~10-15% of live sites will remain Unknown (custom builds, WAFs, JS-only rendering)
- Hosting detection is less reliable when a site is behind Cloudflare (hides origin)
- Does not distinguish "migrated to Shopify" from "was always on Shopify alongside your service"
- Wappalyzer cache can become stale — delete `.wappalyzer_cache.json` to refresh signatures
