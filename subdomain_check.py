#!/usr/bin/env python3
import argparse
import socket
import requests
import concurrent.futures
import csv
import json
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def get_ip_owner(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        netname = res.get('network', {}).get('name')
        orgname = res.get('network', {}).get('org', '')
        if not netname and 'entities' in res:
            for ent in res['entities']:
                try:
                    ent_info = obj.lookup_rdap(depth=1, asn_methods=['whois'], entity=ent)
                    orgname = ent_info.get('objects', {}).get(ent, {}).get('contact', {}).get('name', orgname)
                    if orgname:
                        break
                except Exception:
                    continue
        return orgname or netname or "Unknown"
    except IPDefinedError:
        return "Private/Reserved IP"
    except Exception as e:
        return f"WHOIS error: {str(e)}"

def check_dns(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return True, ip
    except Exception:
        return False, None

def check_web(subdomain):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SubdomainChecker/1.0)"
    }
    urls = [f"https://{subdomain}", f"http://{subdomain}"]
    for url in urls:
        try:
            resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True, verify=True)
            status_code = resp.status_code
            scheme = "HTTPS" if url.startswith("https") else "HTTP"
            # Consider 2xx,3xx,4xx,5xx as active web, 1xx rare and usually no content, but up to you
            if 100 <= status_code < 600:
                return True, f"{scheme} AKTIF (HTTP {status_code})"
        except requests.exceptions.SSLError:
            # SSL error means https might not be valid, try http
            if url.startswith("https"):
                continue
        except Exception:
            continue
    return False, "WEB TIDAK AKTIF"

def detect_hosting_type(ip_owner):
    # Basic heuristic based on keywords
    cdn_providers = ['cloudflare', 'akamai', 'fastly', 'amazon cloudfront', 'cloudfront']
    cloud_providers = ['amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure', 'digitalocean', 'linode', 'vultr', 'hetzner']

    lowered = ip_owner.lower()
    for cdn in cdn_providers:
        if cdn in lowered:
            return "CDN"
    for cloud in cloud_providers:
        if cloud in lowered:
            return "Cloud Hosting"
    # VPS or Shared - simplistic, if owner contains "hosting" or "vps"
    if "hosting" in lowered or "vps" in lowered or "server" in lowered:
        return "VPS/Hosting"
    return "Dedicated/Unknown"

def process_subdomain(subdomain):
    subdomain = subdomain.strip()
    if not subdomain:
        return None
    dns_active, ip = check_dns(subdomain)
    if dns_active:
        ip_owner = get_ip_owner(ip)
        hosting_type = detect_hosting_type(ip_owner)
        web_active, web_status = check_web(subdomain)
    else:
        ip = "-"
        ip_owner = "-"
        hosting_type = "-"
        web_active = False
        web_status = "WEB TIDAK AKTIF"
    return {
        'subdomain': subdomain,
        'dns_active': dns_active,
        'ip': ip,
        'ip_owner': ip_owner,
        'hosting_type': hosting_type,
        'web_active': web_active,
        'web_status': web_status
    }

def save_txt(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for r in results:
            line = (f"{r['subdomain']} --> DNS: {'AKTIF' if r['dns_active'] else 'TIDAK AKTIF'} "
                    f"({r['ip']}) | WEB: {r['web_status']} | Owner: {r['ip_owner']} | Hosting: {r['hosting_type']}")
            f.write(line + "\n")

def save_csv(results, filename):
    fieldnames = ['subdomain', 'dns_active', 'ip', 'ip_owner', 'hosting_type', 'web_active', 'web_status']
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

def save_json(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(description='Subdomain DNS and Web status checker with IP owner lookup.')
    parser.add_argument('target', nargs='?', help='Single subdomain to check')
    parser.add_argument('-d', '--domain-file', help='File containing list of subdomains, one per line')
    parser.add_argument('-o', '--output', help='Output file name (supports .txt, .csv, .json or no extension)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    args = parser.parse_args()

    targets = []
    if args.target:
        targets = [args.target]
    elif args.domain_file:
        try:
            with open(args.domain_file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading domain file: {e}")
            return
    else:
        print("Error: You must specify either a single subdomain or a domain list file (-d).")
        parser.print_help()
        return

    results = []
    print(f"Starting checks for {len(targets)} target(s)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_subdomain, sub): sub for sub in targets}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                # Print to terminal
                print(f"{res['subdomain']} --> DNS: {'AKTIF' if res['dns_active'] else 'TIDAK AKTIF'} "
                      f"({res['ip']}) | WEB: {res['web_status']} | Owner: {res['ip_owner']} | Hosting: {res['hosting_type']}")

    if args.output:
        base = args.output
        if base.lower().endswith('.txt'):
            save_txt(results, base)
            print(f"[+] TXT output saved to {base}")
        elif base.lower().endswith('.csv'):
            save_csv(results, base)
            print(f"[+] CSV output saved to {base}")
        elif base.lower().endswith('.json'):
            save_json(results, base)
            print(f"[+] JSON output saved to {base}")
        else:
            # No extension - save all three formats with the given base name
            save_txt(results, base + ".txt")
            save_csv(results, base + ".csv")
            save_json(results, base + ".json")
            print(f"[+] TXT, CSV, and JSON outputs saved as {base}.txt, {base}.csv, {base}.json")

if __name__ == "__main__":
    main()
