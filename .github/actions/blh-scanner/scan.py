"""
MISS Framework - BLH Scanner (scan.py)
VERSION 2.2 - Fixed typo in argparse (parser.add.argument -> parser.add_argument)
VERSION 2.1 - Removed file extension filter to scan *all* files.
Upgraded to specifically detect S3 'NoSuchBucket'
and Azure 'ContainerNotFound' errors, in addition to dangling DNS.

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
import time

# REGEX to find URLs.
URL_REGEX = r'https?://[^\s"\'()<>\[\]]+'

# Directories to ignore
IGNORE_DIRS = ('.git', '.github', 'node_modules', 'dist', 'build', '.venv')

# Custom User-Agent
REQUEST_HEADERS = {
    'User-Agent': 'MISS-Framework-Scanner/2.2'
}

def find_links_in_file(filepath):
    """Finds all unique URLs in a single file."""
    links = set()
    try:
        # We attempt to read every file as text.
        # If it's a binary file, the read() will fail and the
        # exception block will catch it and safely skip the file.
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for match in re.finditer(URL_REGEX, content):
                links.add(match.group(0))
    except Exception:
        pass # Ignore binary files or read errors
    return links

def check_http_status(url):
    """
    Performs a HEAD request for a quick status check.
    This is for generic domains, not the special S3/Azure checks.
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True, headers=REQUEST_HEADERS)
        if 400 <= response.status_code <= 499:
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

def check_s3_bucket(url):
    """
    Specific check for S3 'NoSuchBucket' vulnerability.
    This is the Reddit rpan-studio case.
    """
    try:
        # We must use GET, not HEAD, to read the XML response body.
        response = requests.get(url, timeout=5, headers=REQUEST_HEADERS)
        
        # Check for the specific XML error code
        if response.status_code == 404 and "<Code>NoSuchBucket</Code>" in response.text:
            return "Broken", "CRITICAL: S3 bucket does not exist and is available for registration ('NoSuchBucket')."
        
        if response.status_code == 200:
             return "OK", None

        return f"Info ({response.status_code})", None # Exists, but not 200 (e.g., 403 Forbidden)
        
    except requests.exceptions.Timeout:
        return "Broken (Timeout)", None
    except requests.exceptions.ConnectionError:
        return "Broken (Connection Error)", None
    except Exception:
        return "Broken (Unknown Error)", None

def check_azure_blob(url):
    """Specific check for Azure Blob 'ContainerNotFound' vulnerability."""
    try:
        # Azure also returns an XML body on a GET request
        response = requests.get(url, timeout=5, headers=REQUEST_HEADERS)
        
        # Check for the specific XML error code
        if response.status_code == 404 and "<Code>ContainerNotFound</Code>" in response.text:
            return "CRITICAL: Azure Blob container does not exist and is available for registration ('ContainerNotFound')."
        
        if response.status_code == 200:
            return "OK", None
            
        return f"Info ({response.status_code})", None
        
    except requests.exceptions.Timeout:
        return "Broken (Timeout)", None
    except requests.exceptions.ConnectionError:
        return "Broken (Connection Error)", None
    except Exception:
        return "Broken (Unknown Error)", None

def check_dangling_dns(domain):
    """
    This is the original check, now only for custom domains.
    It checks for expired domains or CNAMEs pointing to non-existent resources.
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
        cname_records = dns.resolver.resolve(domain, 'CNAME')
        if not cname_records:
            return "Warning: Link is broken, but hijack vector not automatically confirmed (No CNAME)."
        
        cname_target = cname_records[0].target.to_text(omit_final_dot=True)
        
        # Now, does that CNAME *target* resource exist?
        try:
            dns.resolver.resolve(cname_target)
        except dns.resolver.NXDOMAIN:
            # The target resource does *NOT* exist. This is a classic dangling DNS!
            return f"CRITICAL: Dangling DNS. CNAME points to non-existent resource: {cname_target}"
        except dns.resolver.NoAnswer:
            pass # Can't be sure

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NoMetaqueries):
        # The custom domain itself doesn't exist.
        return "Warning: Domain does not resolve (NXDOMAIN)."
    except dns.resolver.NoRootSOA:
        # A common whois guard
        return "Warning: Domain does not resolve (NoRootSOA)."
    except Exception:
        pass # Other DNS errors
        
    return "Warning: Link is broken, but hijack vector not automatically confirmed."

def main():
    parser = argparse.ArgumentParser(description="MISS Framework BLH Scanner")
    parser.add_argument("--directory", default=".", help="Directory to scan")
    
    # --- FIX ---
    # Changed parser.add.argument to parser.add_argument
    parser.add_argument("--output", default="blh_report.json", help="Output JSON report file")
    # --- END FIX ---
    
    args = parser.parse_args()

    print(f"Starting BLH Scan in: {args.directory}")
    print("Scanning ALL file types...")
    
    all_links = set()
    file_map = {}

    for root, dirs, files in os.walk(args.directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        # Removed the 'if file.endswith(SCAN_EXTENSIONS):' check.
        # Now we process *every* file.
        for file in files:
            filepath = os.path.join(root, file)
            links_in_file = find_links_in_file(filepath)
            for link in links_in_file:
                all_links.add(link)
                if link not in file_map:
                    file_map[link] = []
                file_map[link].append(filepath)

    print(f"Found {len(all_links)} unique links. Analyzing...")
    
    results = []
    
    for i, link in enumerate(all_links):
        print(f"Checking [{i+1}/{len(all_links)}] {link}...")
        
        domain = urlparse(link).hostname
        if not domain:
            print(f"  -> INFO: Skipping link with no domain: {link}")
            continue
        
        status = "OK"
        vulnerability = None

        # Route to the correct checker
        if 's3.amazonaws.com' in domain:
            status, vulnerability = check_s3_bucket(link)
        elif 'blob.core.windows.net' in domain:
            status, vulnerability = check_azure_blob(link)
        else:
            # Generic domain check
            status = check_http_status(link)
            if status != "OK":
                vulnerability = check_dangling_dns(domain)
        
        # Rate limit to avoid being blocked
        time.sleep(0.1) 

        if status != "OK":
            result = {
                "link": link,
                "status": status,
                "domain": domain,
                "vulnerability_type": vulnerability,
                "found_in": file_map[link]
            }
            print(f"  -> VULNERABLE: {status} - {vulnerability}")
            results.append(result)

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

