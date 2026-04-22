# domain-analyzer

When customers cancel or churn, most analyses stop at "they left." This tool tells you where they went.

Feed it a CSV of canceled services and it checks whether each domain is still live, what platform it's running on now (Shopify, WooCommerce, Magento, Squarespace, and a dozen others), and who's hosting it. Two passes: fast HTTP fingerprinting first, then a deeper Wappalyzer signature scan for sites that couldn't be identified in round one.

Built for product managers who need post-churn competitive intelligence without waiting on engineering.

## What you get

An enriched CSV with these columns added to your input:

| Column | What it tells you |
|---|---|
| `DNS_RESOLVES` | Is the domain still live? |
| `PLATFORM` | What platform are they on now? |
| `HOSTING_PROVIDER` | Who's hosting them? |
| `CONFIDENCE` | How confident is the detection? |
| `BUILTWITH_FOLLOWUP` | Site is live but platform unknown — possible custom build or WAF |

## Usage

### As a Claude Code skill

Drop this folder into your Claude Code workspace's `.claude/skills/` directory and invoke it with `/domain-analysis`.

Claude will walk you through the analysis, ask about any internal staging domains to skip, and print a platform breakdown summary when done.

### Run the scripts directly

```bash
pip install requests ipwhois

# Pass 1: DNS resolution + HTTP fingerprinting
python3 domain_lookup.py --input ~/Downloads/canceled_services.csv --output results.csv

# Pass 2: Wappalyzer signatures for undetected sites
python3 domain_lookup_wappalyzer_pass.py --file results.csv
```

If you have internal staging domains to skip (so they don't get checked as real customer domains):

```bash
python3 domain_lookup.py \
  --input services.csv \
  --output results.csv \
  --skip-suffix .staging.example.com,.preview.example.com
```

## Input format

Your CSV needs at least one of these columns:

- `PRIMARY_DOMAIN`
- `SITE_DOMAIN`
- `CLIENT_DOMAIN`

Rows with blank domains or domains matching your `--skip-suffix` list are marked `NO_REAL_DOMAIN` and skipped.

## Performance

About 10-20 minutes for 500 domains at 25 concurrent workers. The Wappalyzer pass adds another few minutes for undetected sites.

Wappalyzer signatures are cached locally in `.wappalyzer_cache.json` after the first download. Delete that file to force a refresh.

## Platforms detected

Shopify, WooCommerce, BigCommerce, Shopware, Magento, Squarespace, Wix, Webflow, WordPress, PrestaShop, OpenCart, Salesforce Commerce Cloud, Shift4Shop / 3dcart, Volusion

## Limitations

- 10-15% of live sites stay `Unknown` — custom builds and sites behind WAFs resist fingerprinting
- Hosting detection is less reliable when a CDN like Cloudflare is masking the origin server
- Can't distinguish "migrated to Shopify" from "was always on Shopify alongside your service"

## Requirements

Python 3.9+, `requests`, `ipwhois`
