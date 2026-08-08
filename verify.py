#!/usr/bin/env python3
"""
Security Verification Pipeline
Fetches CVE data from NVD API 2.0, cross-references against CISA KEV.
"""
import argparse, json, os, sys
from datetime import datetime, timedelta, timezone
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_nvd(vendor=None, cve_id=None, hours=24):
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    params = {}
    if cve_id:
        params["cveId"] = cve_id
    elif vendor:
        params["cpeName"] = f"cpe:2.3:a:{vendor}:*:*:*:*:*:*:*:*:*"
    if not cve_id:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    resp = requests.get(NVD_API, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def fetch_cisa_kev():
    resp = requests.get(CISA_KEV, timeout=30)
    resp.raise_for_status()
    return resp.json()

def cross_reference_kev(cves, kev_data):
    kev_cves = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    for vuln in cves.get("vulnerabilities", []):
        vuln["cve"]["in_kev"] = vuln["cve"]["id"] in kev_cves
    return cves

def generate_report(data, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"cve-report-{datetime.now().strftime('%Y-%m-%d')}.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# CVE Report - {datetime.now().strftime('%Y-%m-%d')}\n\n")
        vulns = data.get("vulnerabilities", [])
        f.write(f"Total CVEs: {len(vulns)}\n\n")
        for vuln in vulns:
            cve = vuln["cve"]
            desc = cve.get("descriptions", [{}])[0].get("value", "N/A")
            cvss = cve.get("metrics", {}).get("cvssMetricV31", [{}])
            score = cvss[0].get("cvssData", {}).get("baseScore", "N/A") if cvss else "N/A"
            f.write(f"## {cve['id']}\n- CVSS: {score}\n- KEV: {'Yes' if cve.get('in_kev') else 'No'}\n- {desc[:200]}\n\n")
    return filepath

def main():
    parser = argparse.ArgumentParser(description="Security Verification Pipeline")
    parser.add_argument("--vendor")
    parser.add_argument("--cve")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--kev-only", action="store_true")
    parser.add_argument("--output", default="./reports")
    args = parser.parse_args()
    data = fetch_nvd(vendor=args.vendor, cve_id=args.cve, hours=args.hours)
    data = cross_reference_kev(data, fetch_cisa_kev())
    if args.kev_only:
        data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v["cve"].get("in_kev")]
    print(f"Report: {generate_report(data, args.output)}")

if __name__ == "__main__":
    main()