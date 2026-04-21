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
- **Pass 1:** `outputs/analyses/domain_lookup.py` — DNS resolution + HTTP fingerprinting via headers/HTML
- **Pass 2:** `outputs/analyses/domain_lookup_wappalyzer_pass.py` — Wappalyzer signatures for BUILTWITH_FOLLOWUP=yes rows

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

### Step 4: Run Pass 1
```bash
python3 outputs/analyses/domain_lookup.py \
  --input "[input_path]" \
  --output "[output_path]"
```

**Expected input CSV columns** (at minimum one of these must be present and non-blank):
- `PRIMARY_DOMAIN`, `SITE_DOMAIN`, or `CLIENT_DOMAIN`

Domains ending in `.nxcli.net` or `.nxcli.io` are automatically skipped (Nexcess staging).

### Step 5: Run Pass 2 (Wappalyzer)
```bash
python3 outputs/analyses/domain_lookup_wappalyzer_pass.py \
  --file "[output_path]"
```

The Wappalyzer tech definitions are cached locally in `outputs/analyses/.wappalyzer_cache.json` after the first run. Delete that file to force a refresh.

### Step 6: Print summary
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

**NO_REAL_DOMAIN** — Row had only a temp/staging domain (nxcli.net/io) or blank. No customer domain to check.

**DNS dark / blank PLATFORM** — Domain doesn't resolve. Site is gone or domain expired.

**BUILTWITH_FOLLOWUP=yes** — Site is live but platform couldn't be fingerprinted. Likely a custom build or behind a WAF. BuiltWith paid API ($295/mo) is the next option for these.

**Still on Magento** — Customer left Nexcess but stayed on Magento. Different retention problem than migration. Worth flagging to the Tiger Team.

---

## Limitations

- ~10-15% of live sites will remain Unknown (custom builds, WAFs, JS-only rendering)
- Hosting detection is less reliable when a site is behind Cloudflare (hides origin)
- Does not distinguish "migrated to Shopify" from "was always on Shopify alongside Nexcess"
- Wappalyzer cache can become stale — delete `.wappalyzer_cache.json` to refresh signatures
