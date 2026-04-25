# domain-analyzer

When customers cancel or churn, most analyses stop at "they left." This tool tells you where they went.

Feed it a CSV of canceled services and it checks whether each domain is still live, what platform it's running on now (Shopify, WooCommerce, Magento, Squarespace, and a dozen others), and who's hosting it. Three passes: fast HTTP fingerprinting first, then a deeper Wappalyzer signature scan for undetected sites, then an optional deep-dive pass that pierces Cloudflare proxies using subdomains and Certificate Transparency logs to find managed hosting providers the first two passes can't see.

Built for product managers who need post-churn competitive intelligence without waiting on engineering.

---

## What you can learn

- **Did they leave the platform or just the host?** A customer who said "platform migration" but is still on Magento somewhere is a very different win-back target than one who actually moved to Shopify.
- **Where is the real competition?** Not just which platforms they moved to, but which hosting providers are capturing your churned accounts.
- **Which churn reasons are accurate?** Cross-reference stated cancellation reasons against what their domain actually shows. The gap is often significant.

## What you get

An enriched CSV with these columns added to your input:

| Column | What it tells you |
|---|---|
| `DNS_RESOLVES` | Is the domain still live? |
| `PLATFORM` | What platform are they on now? |
| `HOSTING_PROVIDER` | Who's hosting them? |
| `CONFIDENCE` | How confident is the detection? |
| `BUILTWITH_FOLLOWUP` | Site is live but platform unknown — possible custom build or WAF |

---

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

# Pass 3 (optional): Managed provider detection behind Cloudflare
python3 domain_lookup_deepdive_pass.py --file results.csv --platform Magento
```

If you have internal staging domains to skip:

```bash
python3 domain_lookup.py \
  --input services.csv \
  --output results.csv \
  --skip-suffix .staging.example.com,.preview.example.com
```

### When to run Pass 3

Pass 3 is worth running when you have a meaningful number of domains behind Cloudflare or other WAF proxies and you want to identify whether they're on a managed hosting platform. It uses unproxied subdomains (cpanel., ftp., dev., staging.) and Certificate Transparency logs to find provider-specific fingerprints that survive proxying.

Note: Pass 3 collects DKIM records as raw signals for inspection but does not use them to classify hosting providers. DKIM is email signing infrastructure — it's independent of web hosting and commonly left pointing at old providers long after a migration. Using it to infer web hosting produces false positives.

---

## Input format

Your CSV needs at least one of these columns:

- `PRIMARY_DOMAIN`
- `SITE_DOMAIN`
- `CLIENT_DOMAIN`

Rows with blank domains or domains matching your `--skip-suffix` list are marked `NO_REAL_DOMAIN` and skipped.

---

## Platforms detected

Shopify, WooCommerce, BigCommerce, Shopware, Magento, Squarespace, Wix, Webflow, WordPress, PrestaShop, OpenCart, Salesforce Commerce Cloud, Shift4Shop / 3dcart, Volusion

## Hosting providers detected

Standard detection (Pass 1): Shopify, WP Engine, Kinsta, Nexcess / Liquid Web, Vercel, Netlify, Pantheon, Flywheel, SiteGround, GoDaddy, Cloudflare, AWS, Google Cloud, Fastly, Azure

Managed Magento / PHP providers (Pass 1 + Pass 3): Webscale, JetRails, Platform.sh, Upsun, Cloudways, Rackspace, Pagely, Pressidium, Kinsta, SiteGround

---

## Performance

About 10-20 minutes for 500 domains at 25 concurrent workers. The Wappalyzer pass adds a few minutes for undetected sites. Pass 3 runs at 10 concurrent workers due to rate limits on the Certificate Transparency API.

Wappalyzer signatures are cached locally in `.wappalyzer_cache.json` after the first download. Delete that file to force a refresh.

---

## Limitations

- 10-15% of live sites stay `Unknown` — custom builds and sites behind WAFs resist fingerprinting
- Pass 3 reduces the Cloudflare blind spot but doesn't eliminate it: origins with no unproxied subdomains and no provider-specific CT log SANs remain undetectable
- Can't distinguish "migrated to Shopify" from "was always on Shopify alongside your service"
- Detection accuracy degrades for very new or very small providers not yet in the fingerprint patterns

---

## Requirements

Python 3.9+, `requests`, `ipwhois`
