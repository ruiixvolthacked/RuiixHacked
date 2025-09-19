#!/usr/bin/env python3
"""
RuiixHacked - Personal Bug Bounty Toolkit
File: RuiixHacked.py

Features:
- Interactive terminal menu (rich)
- Recon (calls external tools if available: subfinder, amass, assetfinder)
- Port scan (nmap if available)
- Nuclei scan (if nuclei installed)
- Sensitive-data scanner (scans URLs or local files for secrets)
- Takeover checks (basic CNAME checks)
- Report generation (markdown)
- Themeable colors (default: green theme)
- Big warning banner printed when sensitive data is detected

Usage: python3 RuiixHacked.py

Disclaimer: Use only on targets you have permission to test. For legal/ethical usage only.
"""

from __future__ import annotations
import sys
import os
import re
import subprocess
import json
from datetime import datetime
from typing import List

# Try to import rich. If not available, provide fallback simple output and instructions.
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.theme import Theme
    from rich.markdown import Markdown
    from rich.text import Text
except Exception as e:
    print("[!] This tool requires the 'rich' Python package for colored output.")
    print("    Install with: pip install rich")
    print("    Fallback mode: minimal output enabled.")

    class _Fallback:
        def __getattr__(self, name):
            return lambda *a, **k: None

    Console = _Fallback()
    Panel = lambda *a, **k: None
    Table = lambda *a, **k: None
    Prompt = type("P", (), {"ask": staticmethod(lambda *a, **k: input(a[0] if a else ""))})
    Text = str
    Theme = None
    Markdown = lambda x: x

# Optional but recommended: requests
try:
    import requests
except Exception:
    requests = None

# -------------------------
# Configuration / Theme
# -------------------------
GREEN_THEME = Theme({
    "logo": "bold green",
    "menu": "bold green",
    "info": "green",
    "warn": "bold red",
    "success": "bold green",
    "muted": "dim",
})

DEFAULT_THEME_NAME = "green"

console = Console(theme=GREEN_THEME)

# -------------------------
# Utility functions
# -------------------------

def run_cmd(cmd: List[str], capture: bool = False, timeout: int = 300):
    """Run external command; return stdout if capture True."""
    try:
        if capture:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return result.stdout + result.stderr
        else:
            subprocess.run(cmd)
    except FileNotFoundError:
        return None
    except Exception as e:
        return str(e)


def check_tool(name: str) -> bool:
    """Check if tool is available in PATH"""
    return shutil.which(name) is not None if 'shutil' in globals() else _which_fallback(name)


def _which_fallback(name: str) -> bool:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(path, name)
        if os.path.exists(full) and os.access(full, os.X_OK):
            return True
    return False


# -------------------------
# Sensitive patterns
# -------------------------
SENSITIVE_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?secret(.{0,20})?key[\s:=\"]+([A-Za-z0-9/+=]{40})",
    "Private Key": r"-----BEGIN (RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Generic API Key": r"(?i)api[_-]?key[\s:=\"]+([A-Za-z0-9\-_]{16,64})",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{10,})",
    "Private IP": r"\b(?:10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)",
    "Passwords in URL": r"https?://[^\s@]+:[^\s@]+@",
}

COMPILED_PATTERNS = [(k, re.compile(v)) for k, v in SENSITIVE_PATTERNS.items()]


# -------------------------
# Core features
# -------------------------

def print_logo(theme_name: str = DEFAULT_THEME_NAME):
    logo = r"""
  ____  _ _ _    _ _        _   _                _
 |  _ \(_) (_)  (_) |_ __ _| | | | ___  ___  ___| |_
 | |_) | | | | | | __/ _` | |_| |/ _ \/ __|/ _ \ __|
 |  _ <| | | | | | || (_| |  _  | (_) \__ \  __/ |_
 |_| \_\_|_|_| |_|\__\__,_|_| |_|\___/|___/\___|\__|

           RuiixHacked - personal bug bounty toolkit
    """
    console.print(Panel(Text(logo), style="logo"))


def menu() -> None:
    print_logo()
    table = Table(show_header=False, box=None)
    table.add_row("1.", Text("Recon: subdomains discovery (subfinder/assetfinder/amass)", style="menu"))
    table.add_row("2.", Text("Port scan: nmap (if installed)", style="menu"))
    table.add_row("3.", Text("Nuclei scan (templates)", style="menu"))
    table.add_row("4.", Text("Sensitive Data Scan (URLs or local files)", style="menu"))
    table.add_row("5.", Text("Takeover checks (basic CNAME checks)", style="menu"))
    table.add_row("6.", Text("Generate Report (markdown)", style="menu"))
    table.add_row("7.", Text("Settings: theme / output folder", style="menu"))
    table.add_row("0.", Text("Exit", style="menu"))
    console.print(table)


def recon(target: str, output_dir: str):
    console.print(f"Starting recon for: {target}", style="info")
    os.makedirs(output_dir, exist_ok=True)
    results = {}

    # assetfinder
    out_asset = run_cmd(["assetfinder", "--subs-only", target], capture=True)
    if out_asset is not None:
        results['assetfinder'] = out_asset
        with open(os.path.join(output_dir, "assetfinder.txt"), "w") as f:
            f.write(out_asset)
    else:
        console.print("assetfinder not found or failed", style="muted")

    # subfinder
    out_sub = run_cmd(["subfinder", "-d", target, "-silent"], capture=True)
    if out_sub is not None:
        results['subfinder'] = out_sub
        with open(os.path.join(output_dir, "subfinder.txt"), "w") as f:
            f.write(out_sub)
    else:
        console.print("subfinder not found or failed", style="muted")

    # amass
    out_amass = run_cmd(["amass", "enum", "-passive", "-d", target], capture=True)
    if out_amass is not None:
        results['amass'] = out_amass
        with open(os.path.join(output_dir, "amass.txt"), "w") as f:
            f.write(out_amass)
    else:
        console.print("amass not found or failed", style="muted")

    console.print("Recon finished. Outputs saved to " + output_dir, style="success")
    return results


def port_scan(target: str, output_dir: str):
    console.print(f"Starting nmap scan for: {target}", style="info")
    os.makedirs(output_dir, exist_ok=True)
    out = run_cmd(["nmap", "-sV", "-oA", os.path.join(output_dir, "nmap"), target], capture=True)
    if out is None:
        console.print("nmap not found or failed", style="muted")
        return ""
    console.print("Nmap finished.", style="success")
    return out


def nuclei_scan(target: str, output_dir: str, templates: str = ""):
    console.print(f"Starting nuclei scan for: {target}", style="info")
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["nuclei", "-u", target, "-o", os.path.join(output_dir, "nuclei.txt")]
    if templates:
        cmd.extend(["-t", templates])
    out = run_cmd(cmd, capture=True)
    if out is None:
        console.print("nuclei not found or failed", style="muted")
        return ""
    console.print("Nuclei finished.", style="success")
    return out


def sensitive_scan_urls(urls: List[str], output_dir: str) -> List[dict]:
    """Fetch each URL and check content for sensitive patterns."""
    findings = []
    os.makedirs(output_dir, exist_ok=True)
    headers = {"User-Agent": "RuiixHacked/1.0"}

    if requests is None:
        console.print("requests package not installed. Install with: pip install requests", style="warn")
        return findings

    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            text = r.text
            url_findings = []
            for name, patt in COMPILED_PATTERNS:
                for m in patt.finditer(text):
                    snippet = m.group(0)[:200]
                    url_findings.append({"type": name, "match": snippet, "url": url})
            if url_findings:
                findings.extend(url_findings)
                # write a file with the response
                safename = re.sub(r"[^0-9A-Za-z._-]", "_", url)[:120]
                with open(os.path.join(output_dir, f"response_{safename}.html"), "w", encoding="utf-8") as f:
                    f.write(text)
        except Exception as e:
            console.print(f"Failed to fetch {url}: {e}", style="muted")
    # If any findings, print warning banner
    if findings:
        warn_banner(findings)
    else:
        console.print("No sensitive patterns detected in provided URLs.", style="success")
    # save findings as JSON
    with open(os.path.join(output_dir, "sensitive_findings.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    return findings


def sensitive_scan_filepaths(paths: List[str], output_dir: str) -> List[dict]:
    findings = []
    os.makedirs(output_dir, exist_ok=True)
    for p in paths:
        if not os.path.exists(p):
            console.print(f"Path not found: {p}", style="muted")
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for name, patt in COMPILED_PATTERNS:
                for m in patt.finditer(content):
                    snippet = m.group(0)[:200]
                    findings.append({"type": name, "match": snippet, "file": p})
        except Exception as e:
            console.print(f"Could not read {p}: {e}", style="muted")
    if findings:
        warn_banner(findings)
    else:
        console.print("No sensitive patterns detected in provided files.", style="success")
    with open(os.path.join(output_dir, "sensitive_findings.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    return findings


def warn_banner(findings: List[dict]):
    # Big red warning panel and summary
    count = len(findings)
    txt = Text(f"SENSITIVE DATA DETECTED: {count} potential matches\n", style="warn")
    txt.append("\nPLEASE HANDLE WITH CARE — THIS MAY INCLUDE API KEYS, PRIVATE KEYS, PASSWORDS, OR TOKENS\n", style="warn")
    txt.append("DO NOT SHARE THESE IN PUBLIC REPORTS. Mask or redact before submission.\n\n", style="warn")
    # show top 5 examples
    for f in findings[:5]:
        typ = f.get('type')
        match = f.get('match')
        loc = f.get('url', f.get('file', 'unknown'))
        txt.append(f"- {typ} in {loc}: {match[:120]}\n")
    console.print(Panel(txt, title="!!! ALERT !!!", style="warn"))


def takeover_check(domain: str, output_dir: str) -> List[str]:
    """Very basic takeover check: look for common CNAME targets that are unclaimed services.
    This is a heuristic — for thorough checks use specialised scanners.
    """
    checks = []
    try:
        import dns.resolver
    except Exception:
        console.print("dnspython not installed (pip install dnspython). Skipping takeover checks.", style="muted")
        return checks

    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for r in answers:
            target = str(r.target).rstrip('.')
            checks.append(target)
            console.print(f"CNAME -> {target}", style="info")
    except Exception:
        console.print("No CNAME record or failed to resolve.", style="muted")
    # Basic heuristic: look for known cloud service indicators
    risky = [t for t in checks if any(x in t for x in ['heroku', 'github', 'amazonaws', 's3', 'azurewebsites', 'azureedge', 'cloudfront', 'netlify', 'surge.sh'])]
    if risky:
        console.print("Potential takeover-risk CNAME targets detected:", style="warn")
        for r in risky:
            console.print(f" - {r}", style="warn")
    else:
        console.print("No immediate takeover indicators found.", style="success")
    return checks


def generate_report(output_dir: str, report_name: str = "report.md"):
    """Collect outputs and create a simple markdown report."""
    md = []
    md.append(f"# RuiixHacked Report\nGenerated: {datetime.utcnow().isoformat()}Z\n")

    for fname in sorted(os.listdir(output_dir)):
        if fname.endswith('.txt') or fname.endswith('.json') or fname.endswith('.html'):
            md.append(f"## {fname}\n```")
            try:
                with open(os.path.join(output_dir, fname), 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.read(4000)
                md.append(lines)
            except Exception as e:
                md.append(f"Could not read {fname}: {e}")
            md.append("```\n")

    report_path = os.path.join(output_dir, report_name)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))
    console.print(f"Report generated: {report_path}", style="success")
    return report_path


# -------------------------
# Settings / Runner
# -------------------------
import shutil

DEFAULT_OUTPUT = os.path.join(os.getcwd(), "RuiixHacked_output")


def settings_menu(config: dict):
    console.print("Settings - current:\n" + json.dumps(config, indent=2), style="muted")
    k = Prompt.ask("Enter setting to change (theme/output/clear) or 'back'")
    if k.lower() == 'theme':
        t = Prompt.ask("Theme (green/blue/red) [green]")
        if t == 'green':
            console.theme = GREEN_THEME
        # add other themes if needed
        config['theme'] = t
    elif k.lower() == 'output':
        val = Prompt.ask("Output folder", default=config.get('output', DEFAULT_OUTPUT))
        config['output'] = val
    elif k.lower() == 'clear':
        confirm = Prompt.ask("Clear output folder? (yes/no)")
        if confirm.lower() == 'yes':
            import shutil
            shutil.rmtree(config.get('output', DEFAULT_OUTPUT), ignore_errors=True)
            console.print("Output cleared.", style="success")
    return config


def main():
    # Basic config
    config = {
        'theme': DEFAULT_THEME_NAME,
        'output': DEFAULT_OUTPUT,
    }
    os.makedirs(config['output'], exist_ok=True)

    while True:
        try:
            menu()
            choice = Prompt.ask("Choose an option")
            if choice == '1':
                target = Prompt.ask("Target domain (example.com)")
                out = os.path.join(config['output'], target.replace('/', '_'))
                recon(target, out)
            elif choice == '2':
                target = Prompt.ask("IP or host to scan")
                out = os.path.join(config['output'], 'nmap')
                port_scan(target, out)
            elif choice == '3':
                target = Prompt.ask("Target URL or list file")
                out = os.path.join(config['output'], 'nuclei')
                nuclei_scan(target, out)
            elif choice == '4':
                mode = Prompt.ask("Scan mode: urls/files", choices=["urls", "files"], default="urls")
                out = os.path.join(config['output'], 'sensitive')
                if mode == 'urls':
                    raw = Prompt.ask("Enter comma-separated URLs or path to file containing URLs")
                    if os.path.exists(raw):
                        with open(raw, 'r') as f:
                            urls = [l.strip() for l in f if l.strip()]
                    else:
                        urls = [u.strip() for u in raw.split(',') if u.strip()]
                    sensitive_scan_urls(urls, out)
                else:
                    raw = Prompt.ask("Enter comma-separated file paths")
                    paths = [p.strip() for p in raw.split(',') if p.strip()]
                    sensitive_scan_filepaths(paths, out)
            elif choice == '5':
                domain = Prompt.ask("Domain to check (example.com)")
                out = os.path.join(config['output'], 'takeover')
                takeover_check(domain, out)
            elif choice == '6':
                p = Prompt.ask("Output folder to collect (default: config output)", default=config['output'])
                generate_report(p)
            elif choice == '7':
                config = settings_menu(config)
            elif choice == '0':
                console.print("Goodbye. Use responsibly.", style="muted")
                break
            else:
                console.print("Unknown option", style="muted")
        except KeyboardInterrupt:
            console.print("\nInterrupted by user. Exiting.", style="muted")
            break


if __name__ == '__main__':
    main()
