# sitemap-analyzer
Analyze a domain's sitemap and return the unique url count (including nested sitemaps)

# Setup
```
git clone https://github.com/ssstonebraker/sitemap-analyzer
cd sitemap-analyzer
pip3 install requests
```
# Usage
```
python3 sitemap-analyzer.py --domain whitehouse.gov
```

# Example:
```
python3 sitemap-analyzer.py --domain whitehouse.gov
2025-01-29 09:46:54,571 - INFO - Starting analysis for whitehouse.gov

Sitemap Analysis Report
=====================
Domain: whitehouse.gov
Total Unique URLs: 133

Content Sections:
- about-the-white-house: 4 URLs
- administration: 6 URLs
- briefings-statements: 16 URLs
- copyright: 1 URLs
- executive-actions: 1 URLs
- executive-orders: 1 URLs
- fact-sheets: 18 URLs
- issues: 1 URLs
- news: 1 URLs
- presidential-actions: 69 URLs
- privacy: 1 URLs
- remarks: 13 URLs

URL Hierarchy:
- Level 0: 1 URLs
- Level 1: 12 URLs
- Level 2: 8 URLs
- Level 4: 112 URLs

Last Modified Date Range:
- Earliest: 2025-01-20T20:12:50+00:00
- Latest: 2025-01-29T14:20:47+00:00
```
