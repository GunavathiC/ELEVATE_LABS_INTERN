import requests
import urllib.parse
import sys
import json
import csv
from datetime import datetime
import re
from bs4 import BeautifulSoup
import warnings
import os
warnings.filterwarnings('ignore')

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.sqli_payloads = ["' OR '1'='1", "1' UNION SELECT NULL--", "' OR 1=1--", "admin'--"]
        self.xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        self.security_headers = {
            'X-Frame-Options': 'medium',
            'X-Content-Type-Options': 'low',
            'Strict-Transport-Security': 'high',
            'Content-Security-Policy': 'medium'
        }

    def print_banner(self):
        print(f"""
{Colors.CYAN}{'='*70}
    WEB VULNERABILITY SCANNER
{'='*70}{Colors.END}
Target: {self.target_url}
Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.CYAN}{'='*70}{Colors.END}
""")

    def add_vulnerability(self, vuln_type, severity, description, url, **kwargs):
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.vulnerabilities.append(vuln)
        color = Colors.FAIL if severity == 'critical' else Colors.WARNING if severity == 'high' else Colors.BLUE
        print(f"{color}[{severity.upper()}] {vuln_type}{Colors.END}")
        print(f"  └─ {description[:80]}...")

    def test_sql_injection(self):
        print(f"\n{Colors.HEADER}[*] Testing SQL Injection...{Colors.END}")
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:2]:
                action = form.get('action', '')
                form_url = urllib.parse.urljoin(self.target_url, action)
                inputs = form.find_all('input')
                
                for inp in inputs:
                    if inp.get('type') in ['text', 'search']:
                        param = inp.get('name', 'q')
                        for payload in self.sqli_payloads[:2]:
                            try:
                                data = {param: payload}
                                r = self.session.get(form_url, params=data, timeout=5, verify=False)
                                if any(err in r.text.lower() for err in ['sql', 'mysql', 'syntax']):
                                    self.add_vulnerability('SQL Injection', 'critical',
                                        f'SQL injection in parameter "{param}"', form_url,
                                        parameter=param, payload=payload, cwe='CWE-89')
                                    break
                            except:
                                continue
        except Exception as e:
            print(f"{Colors.FAIL}  └─ Error: {str(e)[:50]}{Colors.END}")

    def test_xss(self):
        print(f"\n{Colors.HEADER}[*] Testing XSS...{Colors.END}")
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:2]:
                action = form.get('action', '')
                form_url = urllib.parse.urljoin(self.target_url, action)
                inputs = form.find_all('input')
                
                for inp in inputs:
                    if inp.get('type') in ['text', 'search']:
                        param = inp.get('name', 'q')
                        for payload in self.xss_payloads[:1]:
                            try:
                                data = {param: payload}
                                r = self.session.get(form_url, params=data, timeout=5, verify=False)
                                if payload in r.text:
                                    self.add_vulnerability('Cross-Site Scripting (XSS)', 'high',
                                        f'XSS in parameter "{param}"', form_url,
                                        parameter=param, payload=payload, cwe='CWE-79')
                                    break
                            except:
                                continue
        except Exception as e:
            print(f"{Colors.FAIL}  └─ Error: {str(e)[:50]}{Colors.END}")

    def test_security_headers(self):
        print(f"\n{Colors.HEADER}[*] Checking Security Headers...{Colors.END}")
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            for header, severity in self.security_headers.items():
                if header not in response.headers:
                    self.add_vulnerability('Missing Security Header', severity,
                        f'Missing {header}', self.target_url, header=header, cwe='CWE-693')
        except Exception as e:
            print(f"{Colors.FAIL}  └─ Error: {str(e)[:50]}{Colors.END}")

    def test_ssl_tls(self):
        print(f"\n{Colors.HEADER}[*] Checking SSL/TLS...{Colors.END}")
        if self.target_url.startswith('http://'):
            self.add_vulnerability('Insecure Transport', 'high',
                'Using HTTP instead of HTTPS', self.target_url, cwe='CWE-319')

    def scan(self):
        self.print_banner()
        print(f"\n{Colors.CYAN}[*] Starting scan...{Colors.END}\n")
        self.test_sql_injection()
        self.test_xss()
        self.test_security_headers()
        self.test_ssl_tls()
        self.print_summary()
        return self.vulnerabilities

    def print_summary(self):
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulnerabilities:
            counts[v['severity']] += 1
        print(f"""
{Colors.CYAN}{'='*70}
    SCAN COMPLETE
{'='*70}{Colors.END}
{Colors.FAIL}Critical: {counts['critical']}{Colors.END}
{Colors.WARNING}High:     {counts['high']}{Colors.END}
{Colors.BLUE}Medium:   {counts['medium']}{Colors.END}
{Colors.GREEN}Low:      {counts['low']}{Colors.END}
{Colors.BOLD}Total:    {len(self.vulnerabilities)}{Colors.END}
{Colors.CYAN}{'='*70}{Colors.END}""")

    def export_reports(self):
        os.makedirs('reports', exist_ok=True)
        
        # JSON Report
        with open('reports/scan_report.json', 'w', encoding='utf-8') as f:
            json.dump({
                'scan_date': datetime.now().isoformat(),
                'target': self.target_url,
                'total': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        print(f"{Colors.GREEN}[+] JSON: reports/scan_report.json{Colors.END}")
        
        # CSV Report - FIXED to handle different fields
        if self.vulnerabilities:
            # Collect ALL unique keys from all vulnerabilities
            all_keys = set()
            for vuln in self.vulnerabilities:
                all_keys.update(vuln.keys())
            
            # Sort keys for consistent column order
            fieldnames = sorted(list(all_keys))
            
            with open('reports/scan_report.csv', 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                # Fill missing fields with empty string
                for vuln in self.vulnerabilities:
                    row = {key: vuln.get(key, '') for key in fieldnames}
                    writer.writerow(row)
            print(f"{Colors.GREEN}[+] CSV: reports/scan_report.csv{Colors.END}")
        
        # HTML Report
        self.create_html_report()

    def create_html_report(self):
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulnerabilities:
            counts[v['severity']] += 1
        
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Vulnerability Scan Report</title>
<style>
body{{font-family:Arial;margin:40px;background:#f5f5f5}}
.container{{max-width:1200px;margin:0 auto;background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}
h1{{color:#333;border-bottom:3px solid #00acc1;padding-bottom:10px}}
.summary{{display:flex;gap:20px;margin:30px 0}}
.stat{{flex:1;padding:20px;border-radius:8px;text-align:center}}
.stat-num{{font-size:36px;font-weight:bold}}
.critical{{background:#ffebee;color:#c62828}}
.high{{background:#fff3e0;color:#ef6c00}}
.medium{{background:#fff9c4;color:#f9a825}}
.low{{background:#e8f5e9;color:#2e7d32}}
.vuln{{border-left:5px solid;margin:20px 0;padding:20px;background:#fafafa;border-radius:5px}}
.vuln.critical{{border-left-color:#c62828}}
.vuln.high{{border-left-color:#ef6c00}}
.vuln.medium{{border-left-color:#f9a825}}
.vuln.low{{border-left-color:#2e7d32}}
.badge{{background:#333;color:white;padding:5px 10px;border-radius:5px;font-size:12px;text-transform:uppercase}}
</style></head><body><div class="container">
<h1>Vulnerability Scan Report</h1>
<p><strong>Target:</strong> {self.target_url}</p>
<p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary">
<div class="stat critical"><div class="stat-num">{counts['critical']}</div><div>Critical</div></div>
<div class="stat high"><div class="stat-num">{counts['high']}</div><div>High</div></div>
<div class="stat medium"><div class="stat-num">{counts['medium']}</div><div>Medium</div></div>
<div class="stat low"><div class="stat-num">{counts['low']}</div><div>Low</div></div>
</div><h2>Detailed Findings ({len(self.vulnerabilities)} vulnerabilities)</h2>"""
        
        for i, v in enumerate(self.vulnerabilities, 1):
            html += f"""<div class="vuln {v['severity']}">
<h3>{i}. {v['type']} <span class="badge">{v['severity']}</span></h3>
<p><strong>Description:</strong> {v['description']}</p>
<p><strong>URL:</strong> {v['url']}</p>"""
            if 'parameter' in v:
                html += f"<p><strong>Parameter:</strong> {v['parameter']}</p>"
            if 'payload' in v:
                html += f"<p><strong>Payload:</strong> {v['payload']}</p>"
            if 'header' in v:
                html += f"<p><strong>Header:</strong> {v['header']}</p>"
            if 'cwe' in v:
                html += f"<p><strong>CWE:</strong> {v['cwe']}</p>"
            html += "</div>"
        
        html += "</div></body></html>"
        
        with open('reports/scan_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Colors.GREEN}[+] HTML: reports/scan_report.html{Colors.END}")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.BOLD}Usage: python scanner.py <url>{Colors.END}")
        print("Example: python scanner.py https://example.com")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith('http'):
        url = 'https://' + url
    
    scanner = VulnerabilityScanner(url)
    scanner.scan()
    scanner.export_reports()
    print(f"\n{Colors.GREEN}[✓] All reports saved in 'reports/' folder{Colors.END}")

if __name__ == '__main__':
    main()
