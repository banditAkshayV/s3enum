#!/usr/bin/env python3

import argparse
import socket
import requests
import ipaddress
import os
import sys
import xml.etree.ElementTree as ET
from urllib.parse import quote

# URL to download AWS IP ranges JSON
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
# Directory to save downloaded files
DOWNLOAD_DIR = "downloaded"

def is_valid_region(region):
    """Check if the AWS region is valid and not 'GLOBAL'."""
    return region is not None and region.upper() != "GLOBAL"

def get_ips_and_cnames(domain):
    """Resolve domain to IP addresses and CNAMEs."""
    try:
        # Get IPv4 addresses (A records)
        ips = sorted({info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        ips = []

    try:
        # Get CNAMEs (aliases)
        cnames = socket.gethostbyname_ex(domain)[1]
    except Exception:
        cnames = []

    return ips, cnames

def download_aws_ip_ranges():
    """Download AWS IP ranges JSON."""
    try:
        response = requests.get(AWS_IP_RANGES_URL, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[-] Failed to get AWS IP ranges: {e}")
        return None

def find_region_for_ip(ip, aws_ranges):
    """Find AWS region(s) that the IP belongs to."""
    ip_obj = ipaddress.ip_address(ip)
    matches = []
    for prefix in aws_ranges.get("prefixes", []):
        cidr = prefix.get("ip_prefix")
        region = prefix.get("region")
        service = prefix.get("service")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr)
            if ip_obj in network:
                matches.append((region, service, cidr, network.prefixlen))
        except Exception:
            continue
    # Sort matches by prefix length (more specific first)
    matches.sort(key=lambda x: -x[3])
    return matches

def build_s3_endpoints(domain, region):
    """Create a list of possible S3 bucket URLs to try."""
    return [
        f"http://{domain}.s3.amazonaws.com",
        f"http://{domain}.s3.{region}.amazonaws.com",
        f"http://{domain}.s3-{region}.amazonaws.com",
        f"http://s3.amazonaws.com/{domain}",
        f"http://s3.{region}.amazonaws.com/{domain}",
        f"http://s3-{region}.amazonaws.com/{domain}",
        f"http://{domain}.s3-website.{region}.amazonaws.com",
        f"http://s3-website.{region}.amazonaws.com/{domain}",
    ]

def try_list_bucket(bucket_name, endpoint_url):
    """Try to list files in the S3 bucket using the endpoint."""
    keys = []
    params = {"list-type": "2"}  # Use AWS S3 ListObjectsV2 API
    url = endpoint_url.rstrip("/") + "/"

    while True:
        try:
            response = requests.get(url, params=params, timeout=10)
        except Exception:
            return None, None

        if response.status_code not in (200, 301, 302):
            return None, response

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            return None, response

        # Handle XML namespace if present
        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'

        # Extract keys (file names)
        for content in root.findall(f".//{ns}Contents"):
            key_elem = content.find(f"{ns}Key")
            if key_elem is not None and key_elem.text:
                keys.append(key_elem.text)

        # Check if the list is truncated (pagination)
        is_truncated = root.findtext(f"{ns}IsTruncated")
        if is_truncated and is_truncated.lower() == "true":
            token = root.findtext(f"{ns}NextContinuationToken")
            params["continuation-token"] = token
        else:
            break

    return keys, response

def download_file(base_url, key, folder):
    """Download a file from S3 bucket to a local folder."""
    os.makedirs(folder, exist_ok=True)
    file_url = base_url.rstrip("/") + "/" + quote(key)
    local_filename = os.path.basename(key) or key.replace("/", "_")
    local_path = os.path.join(folder, local_filename)

    try:
        response = requests.get(file_url, stream=True, timeout=20)
        if response.status_code == 200:
            with open(local_path, "wb") as f:
                for chunk in response.iter_content(8192):
                    if chunk:
                        f.write(chunk)
            print(f"[+] Saved: {local_path}")
            return True
        else:
            print(f"[-] Failed to download {file_url}: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error downloading {file_url}: {e}")
        return False

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Check if a domain uses AWS and try S3 bucket listing.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to check")
    args = parser.parse_args()

    domain = args.domain.strip()
    print(f"[+] Checking domain '{domain}' for AWS usage...")

    # Get IP addresses and CNAMEs for the domain
    ips, cnames = get_ips_and_cnames(domain)
    print(f"    IP addresses: {ips}")
    print(f"    CNAMEs: {cnames}")

    if not ips:
        print("[-] No IP addresses found. Exiting.")
        sys.exit(1)

    # Download AWS IP ranges data
    aws_ranges = download_aws_ip_ranges()
    if not aws_ranges:
        sys.exit(1)

    region_matches = {}
    skipped_regions = {}

    # Check each IP if it belongs to AWS IP ranges
    for ip in ips:
        print(f"[.] Checking IP {ip} against AWS ranges...")
        matches = find_region_for_ip(ip, aws_ranges)
        if matches:
            for region, service, cidr, prefix_len in matches:
                if is_valid_region(region):
                    print(f"  [MATCH] IP {ip} is in {cidr} (Region: {region}, Service: {service})")
                    region_matches.setdefault(region, []).append(ip)
                else:
                    print(f"  [SKIP] IP {ip} in {cidr} with invalid/global region '{region}'")
                    skipped_regions.setdefault(region, []).append(ip)
        else:
            print(f"  [-] IP {ip} not found in AWS IP ranges.")

    if not region_matches:
        print("[-] No valid AWS regions found for any IP. Exiting.")
        sys.exit(1)

    # Try to list S3 buckets for each region
    for region, ips in region_matches.items():
        print(f"\n[+] Domain is in AWS region: {region}")
        endpoints = build_s3_endpoints(domain, region)
        print("[+] Trying these endpoints for bucket listing:")
        for e in endpoints:
            print(f"  - {e}")

        for endpoint in endpoints:
            print(f"\n[+] Trying bucket listing at {endpoint} ...")
            keys, response = try_list_bucket(domain, endpoint)
            if keys:
                print(f"[+] Found {len(keys)} objects at {endpoint}:")
                for k in keys:
                    print(f"  - {k}")
                print(f"[+] Downloading objects to '{DOWNLOAD_DIR}' folder...")
                for k in keys:
                    download_file(endpoint, k, DOWNLOAD_DIR)
                break
            else:
                print("[-] Could not list bucket or no objects found.")

    # Show skipped/global regions if any
    if skipped_regions:
        print("\n[!] Skipped GLOBAL or invalid regions:")
        for region, ips in skipped_regions.items():
            print(f"  Region '{region}': IPs = {ips}")

    print("\n[+] Done.")

if __name__ == "__main__":
    main()
