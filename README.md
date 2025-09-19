# RuiixHacked

RuiixHacked — Personal Bug Bounty Toolkit

**Short description:**  
RuiixHacked is a lightweight, interactive terminal toolkit to help with common bug bounty tasks: subdomain reconnaissance, port scanning, Nuclei scanning, takeover checks, and sensitive-data scanning. This tool is intended for ethical use only — run it only against targets you are authorized to test.

---

## Features

- Interactive terminal menu (powered by `rich`)
- Recon: optional integrations with `assetfinder`, `subfinder`, and `amass`
- Port scanning support via `nmap` (if installed)
- Nuclei scanning support (`nuclei`) with optional templates
- Sensitive-data scanner for URLs and local files (detects patterns like API keys, private keys, JWTs)
- Basic takeover checks using CNAME heuristics (dnspython)
- Report generator: creates a simple `report.md` from collected outputs
- Themeable colors (default green) and configurable output folder
- Clear red alert panel and `sensitive_findings.json` when potential secrets are found

---

## Quick Install

1. Clone the repository or download the single `RuiixHacked.py` file:
```bash
git clone git@github.com:YOUR_USERNAME/RuiixHacked.git
cd RuiixHacked
