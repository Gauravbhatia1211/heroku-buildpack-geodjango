MISS Framework - BLH Scanner
This GitHub Action implements the "Scan" pillar of the MISS (Manage, Inventory, Scan, Secure) framework.
It scans a repository for external URLs and checks for two critical Broken Link Hijacking (BLH) vulnerabilities:
 * Expired Domains: Links to domains that are broken and available for purchase.
 * Dangling DNS: Links to CNAME records that point to deprovisioned cloud resources (e.g., deleted Azure Blobs or S3 Buckets).
Outputs
 * report_path: The path to the generated blh_report.json file.
Example Usage
name: 'BLH Scan Demo'
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run BLH Scanner
        id: blh_scan
        uses: ./path/to/your/blh-scanner # Assumes action is in the same repo

      - name: Upload Scan Report
        uses: actions/upload-artifact@v4
        with:
          name: blh-report
          path: ${{ steps.blh_scan.outputs.report_path }}

