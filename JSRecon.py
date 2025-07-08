import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import os
from colorama import Fore, Style, init

# === INIT COLOR ===
init(autoreset=True)

# === CONFIG ===
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
JS_SAVE_DIR = 'js_files'
EXTRACTED_OUTPUT = 'structured_findings.txt'

# === Ensure folders exist ===
os.makedirs(JS_SAVE_DIR, exist_ok=True)

def print_banner():
    banner = r"""
    
       ░▒▓█▓▒░░▒▓███████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                            
                                                                                      

                         [ JSRecon v1.0 ]
                        github.com/kuna098
    """
    print(Fore.CYAN + Style.BRIGHT + banner)

def get_html(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return response.text
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def extract_js_links(base_url, html):
    soup = BeautifulSoup(html, 'html.parser')
    script_tags = soup.find_all('script')
    js_links = []

    for tag in script_tags:
        src = tag.get('src')
        if src:
            full_url = urljoin(base_url, src)
            js_links.append(full_url)

    return js_links

def download_js(js_url):
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=10)
        filename = os.path.join(JS_SAVE_DIR, urlparse(js_url).path.split('/')[-1] or 'script.js')
        with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(r.text)
        return filename
    except Exception as e:
        print(f"[!] Failed to download {js_url}: {e}")
        return None

def extract_interesting_data(js_code):
    findings = {
        "full_urls": set(),
        "api_paths": set(),
        "file_paths": set(),
        "jwt_tokens": set(),
        "api_keys": set(),
        "secrets": set()
    }

    patterns = {
        "full_urls": r'https?://[\w./?=&%-]+',
        "api_paths": r'/api/[\w\-/]+',
        "file_paths": r'/[\w\-/]+\.[a-z]{2,4}',
        "jwt_tokens": r'[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}',
        "api_keys": r'[\w-]*apikey[\w-]*\s*[=:]\s*["\']?[A-Za-z0-9\-_]{16,}["\']?',
        "secrets": r'(?i)(key|token|secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?'
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, js_code)
        findings[key].update(matches)

    return findings

def merge_findings(all_findings, new_findings):
    for key in all_findings:
        all_findings[key].update(new_findings.get(key, set()))

def main():
    print_banner()
    target = input("Enter full URL to scan (e.g. https://example.com): ").strip()
    print(f"[*] Fetching HTML from {target}...")
    html = get_html(target)
    if not html:
        return

    print("[*] Extracting JavaScript file links...")
    js_urls = extract_js_links(target, html)
    print(f"[*] Found {len(js_urls)} JS files")

    all_findings = {
        "full_urls": set(),
        "api_paths": set(),
        "file_paths": set(),
        "jwt_tokens": set(),
        "api_keys": set(),
        "secrets": set()
    }

    for js_url in js_urls:
        print(f"[+] Downloading and scanning: {js_url}")
        file_path = download_js(js_url)
        if file_path:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                js_code = f.read()
                findings = extract_interesting_data(js_code)
                merge_findings(all_findings, findings)

    print("\n[✓] Extraction complete.")
    with open(EXTRACTED_OUTPUT, 'w') as out:
        for category, items in all_findings.items():
            out.write(f"\n=== {category.upper()} ===\n")
            for item in sorted(items):
                out.write(item + '\n')

    print(f"[+] Structured results saved to {EXTRACTED_OUTPUT}")

if __name__ == '__main__':
    main()
