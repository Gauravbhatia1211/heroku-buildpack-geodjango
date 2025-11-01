"""
MISS Framework - BLH Scanner (scan.py)
This is the core "Scan" pillar prototype. It finds links and checks
if they are not just broken, but *hijackable*.
"""

import os
import re
import requests
import whois
import dns.resolver
import json
import argparse
from urllib.parse import urlparse

# REGEX to find URLs. This is a simple version for a prototype.
URL_REGEX = r'https?://[^\s"\'()<>\[\]]+'

# Common cloud provider patterns to check for dangling DNS
DANGLING_PATTERNS = [
    's3.amazonaws.com',
    'blob.core.windows.net',
    'azurewebsites.net',
    'cloudfront.net',
    'cloudfunctions.net',
]

# File extensions to scan
SCAN_EXTENSIONS = ('.md', '.txt', '.py', '.js', '.ts', '.yml', '.yaml', '.json', '.sh', '.xml', '.html')

# Directories to ignore
IGNORE_DIRS = ('.git', '.github', 'node_modules', 'dist', 'build', '.venv')

def find_links_in_file(filepath):
    """Finds all unique URLs in a single file."""
    links = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for match in re.finditer(URL_REGEX, content):
                links.add(match.group(0))
    except Exception:
        pass # Ignore binary files or read errors
    return links

def check_http_status(url):
    """Checks the HTTP status of a URL. Returns 'Broken' or 'OK'."""
    try:
        # Use HEAD request for efficiency.
        # Allow redirects to follow to the final destination.
        response = requests.head(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'MISS-Framework-Scanner'})
        
        if 400 <= response.status_code <= 499:
            # 404 Not Found, 403 Forbidden, etc.
            return "Broken (Client Error)"
        elif 500 <= response.status_code <= 599:
            return "Broken (Server Error)"
        else:
            return "OK"
    except requests.exceptions.Timeout:
        return "Broken (Timeout)"
    except requests.exceptions.ConnectionError:
        return "Broken (Connection Error)"
    except Exception:
        return "Broken (Unknown Error)"

def check_hijack_vulnerability(domain):
    """
    This is the core logic.
    For a broken domain, it checks if it's hijackable.
    """
    
    # 1. Check for Expired/Available Domain
    try:
        w = whois.query(domain)
        if w is None or "No match for domain" in str(w) or "available for registration" in str(w):
            return "CRITICAL: Domain is available for registration."
    except Exception:
        pass # WHOIS can be unreliable

    # 2. Check for Dangling DNS (CNAME pointing to nothing)
    try:
        # Check if the domain is a CNAME
        cname_records = dns.resolver.resolve(domain, 'CNAME')
        if not cname_records:
            return None # Not a CNAME

        cname_target = cname_records[0].target.to_text(omit_final_dot=True)
        
        # Is it a CNAME to a vulnerable cloud provider?
        is_dangling_target = False
        for pattern in DANGLING_PATTERNS:
            if pattern in cname_target:
                is_dangling_target = True
                break
        
        if not is_dangling_target:
            return "Info: CNAME points to non-cloud target."

        # The CNAME points to a cloud provider.
        # Now, does that *target* resource exist?
        try:
            dns.resolver.resolve(cname_target)
        except dns.resolver.NXDOMAIN:
            # The target resource does *NOT* exist. This is a classic dangling DNS!
            return f"CRITICAL: Dangling DNS. CNAME points to non-existent resource: {cname_target}"
        except dns.resolver.NoAnswer:
            pass # Can't be sure

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        # The domain itself doesn't exist, which we already checked with WHOIS.
        pass
    except Exception:
        pass # Other DNS errors
        
    return "Warning: Link is broken, but hijack vector not automatically confirmed."

def main():
    parser = argparse.ArgumentParser(description="MISS Framework BLH Scanner")
    parser.add_argument("--directory", default=".", help="Directory to scan")
    parser.add_argument("--output", default="blh_report.json", help="Output JSON report file")
    args = parser.parse_args()

    print(f"Starting BLH Scan in: {args.directory}")
    
    all_links = set()
    for root, dirs, files in os.walk(args.directory):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            if file.endswith(SCAN_EXTENSIONS):
                filepath = os.path.join(root, file)
                all_links.update(find_links_in_file(filepath))

    print(f"Found {len(all_links)} unique links. Analyzing...")
    
    results = []
    
    for i, link in enumerate(all_links):
        print(f"Checking [{i+1}/{len(all_links)}] {link}...")
        status = check_http_status(link)
        
        if status != "OK":
            domain = urlparse(link).hostname
            if domain:
                vulnerability = check_hijack_vulnerability(domain)
                result = {
                    "link": link,
                    "status": status,
                    "domain": domain,
                    "vulnerability": vulnerability
                }
                print(f"  -> VULNERABLE: {status} - {vulnerability}")
                results.append(result)
            else:
                print(f"  -> WARNING: Could not parse domain from link: {link}")

    # Write the JSON report
    report_data = {
        "summary": {
            "total_links_scanned": len(all_links),
            "vulnerabilities_found": len(results)
        },
        "vulnerabilities": results
    }
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)

    print(f"\nScan complete. Report saved to {args.output}")

if __name__ == "__main__":
    main()

