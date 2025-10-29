
import requests
import json
import time
import os
import sys
import re
import threading
import pickle
import socket
import struct
from datetime import datetime, timedelta
from urllib.parse import urlparse
from termcolor import colored
from pyfiglet import Figlet
import subprocess
from collections import defaultdict
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import fcntl
import signal
import logging
from pathlib import Path

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings()


class HackerOneAPI:
    def __init__(self, username=None, token=None):
        self.username = username
        self.token = token
        self.base_url = "https://api.hackerone.com/v1"
        self.session = requests.Session()
        if username and token:
            self.session.auth = (username, token)
        self.session.headers.update({'Accept': 'application/json'})
    
    def get_programs(self):
        programs = []
        try:
            if not self.username or not self.token:
                return programs
            
            url = f"{self.base_url}/hackers/programs"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    attrs = item.get('attributes', {})
                    relationships = item.get('relationships', {})
                    
                    if attrs.get('submission_state') != 'open':
                        continue
                    
                    program = {
                        'platform': 'hackerone',
                        'handle': attrs.get('handle'),
                        'name': attrs.get('name'),
                        'url': attrs.get('url'),
                        'offers_bounties': attrs.get('offers_bounties', False),
                        'scope': []
                    }
                    
                    structured_scopes = relationships.get('structured_scopes', {}).get('data', [])
                    if structured_scopes:
                        scope_url = f"{self.base_url}/programs/{program['handle']}/structured_scopes"
                        scope_response = self.session.get(scope_url, timeout=30)
                        if scope_response.status_code == 200:
                            scope_data = scope_response.json()
                            for scope_item in scope_data.get('data', []):
                                scope_attrs = scope_item.get('attributes', {})
                                if scope_attrs.get('eligible_for_submission'):
                                    asset_identifier = scope_attrs.get('asset_identifier')
                                    if asset_identifier:
                                        program['scope'].append(asset_identifier)
                    
                    if program['scope']:
                        programs.append(program)
        
        except Exception as e:
            pass
        
        return programs


class BugcrowdAPI:
    def __init__(self, email=None, password=None):
        self.email = email
        self.password = password
        self.base_url = "https://bugcrowd.com/api"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
        self.authenticated = False
        if email and password:
            self.authenticate()
    
    def authenticate(self):
        try:
            login_url = f"{self.base_url}/users/sign_in"
            response = self.session.get(login_url, timeout=30)
            
            csrf_token = None
            for cookie in self.session.cookies:
                if 'csrf' in cookie.name.lower():
                    csrf_token = cookie.value
                    break
            
            if not csrf_token:
                return False
            
            auth_data = {
                'email': self.email,
                'password': self.password,
                'authenticity_token': csrf_token
            }
            
            response = self.session.post(login_url, json=auth_data, timeout=30)
            self.authenticated = response.status_code == 200
            return self.authenticated
        
        except:
            return False
    
    def get_programs(self):
        programs = []
        try:
            url = "https://bugcrowd.com/programs.json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('programs', []):
                    if item.get('program_status') != 'live':
                        continue
                    
                    program = {
                        'platform': 'bugcrowd',
                        'handle': item.get('code'),
                        'name': item.get('name'),
                        'url': item.get('program_url'),
                        'offers_bounties': item.get('offers_bounty', False),
                        'scope': []
                    }
                    
                    target_groups = item.get('target_groups', [])
                    for group in target_groups:
                        targets = group.get('targets', [])
                        for target in targets:
                            if target.get('in_scope'):
                                name = target.get('name')
                                if name:
                                    program['scope'].append(name)
                    
                    if program['scope']:
                        programs.append(program)
        
        except Exception as e:
            pass
        
        return programs


class PlatformManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.hackerone = None
        self.bugcrowd = None
    
    def setup_hackerone(self, username, token):
        self.hackerone = HackerOneAPI(username, token)
        return self.hackerone
    
    def setup_bugcrowd(self, email, password):
        self.bugcrowd = BugcrowdAPI(email, password)
        return self.bugcrowd
    
    def sync_programs(self):
        synced = []
        
        if self.hackerone:
            programs = self.hackerone.get_programs()
            for program in programs:
                self.save_program(program)
                synced.append(program)
        
        if self.bugcrowd:
            programs = self.bugcrowd.get_programs()
            for program in programs:
                self.save_program(program)
                synced.append(program)
        
        return synced
    
    def save_program(self, program):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            scope_json = json.dumps(program.get('scope', []))
            
            c.execute("""INSERT OR REPLACE INTO programs 
                        (platform, handle, name, scope_json, added_date)
                        VALUES (?, ?, ?, ?, ?)""",
                     (program['platform'],
                      program['handle'],
                      program['name'],
                      scope_json,
                      datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except:
            return False


class PortScanner:
    """Elite port scanning with service detection"""
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090]
    
    EXTENDED_PORTS = list(range(1, 1001)) + [1433, 1521, 2049, 2181, 2375, 2376, 3000,
                                               4243, 4369, 5000, 5432, 5672, 5984, 6379,
                                               7001, 8000, 8081, 8082, 8088, 8181, 8888,
                                               9000, 9092, 9200, 9300, 11211, 27017, 27018,
                                               50000, 50070]
    
    SERVICE_FINGERPRINTS = {
        21: {'name': 'ftp', 'banner_check': True},
        22: {'name': 'ssh', 'banner_check': True},
        23: {'name': 'telnet', 'banner_check': True},
        25: {'name': 'smtp', 'banner_check': True},
        80: {'name': 'http', 'banner_check': False},
        110: {'name': 'pop3', 'banner_check': True},
        143: {'name': 'imap', 'banner_check': True},
        443: {'name': 'https', 'banner_check': False},
        3306: {'name': 'mysql', 'banner_check': True},
        3389: {'name': 'rdp', 'banner_check': False},
        5432: {'name': 'postgresql', 'banner_check': True},
        6379: {'name': 'redis', 'banner_check': True},
        8080: {'name': 'http-proxy', 'banner_check': False},
        8443: {'name': 'https-alt', 'banner_check': False},
        9200: {'name': 'elasticsearch', 'banner_check': False},
        27017: {'name': 'mongodb', 'banner_check': True},
    }
    
    def __init__(self, timeout=2, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.results = {}
        
    def scan_port(self, host, port):
        """Scan single port with connection attempt"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return port
            return None
        except:
            return None
    
    def grab_banner(self, host, port, service_name):
        """Attempt to grab service banner for version detection"""
        banner = None
        version = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            
            # Send protocol-specific probes
            if service_name in ['ftp', 'smtp', 'pop3', 'imap']:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif service_name == 'ssh':
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif service_name == 'mysql':
                data = sock.recv(1024)
                banner = data.decode('utf-8', errors='ignore').strip()
            elif service_name == 'redis':
                sock.send(b'INFO\r\n')
                banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            elif service_name == 'mongodb':
                sock.send(b'\x3a\x00\x00\x00')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif service_name == 'postgresql':
                sock.send(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            
            # Extract version from banner
            if banner:
                version = self.extract_version(banner)
                
        except:
            pass
        
        return banner, version
    
    def extract_version(self, banner):
        """Extract version information from banner"""
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # x.x.x
            r'(\d+\.\d+)',        # x.x
            r'v(\d+\.\d+\.\d+)', # vx.x.x
            r'version\s+(\d+\.\d+)', # version x.x
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def http_version_check(self, url):
        """Check HTTP server version via headers"""
        try:
            r = requests.head(url, timeout=3, verify=False, allow_redirects=True)
            server = r.headers.get('Server', '')
            powered_by = r.headers.get('X-Powered-By', '')
            
            return {
                'server': server,
                'powered_by': powered_by,
                'status': r.status_code
            }
        except:
            return None
    
    def scan_host(self, host, ports='common', fast=True):
        """Scan host with specified port range"""
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except:
            return None
        
        # Select port range
        if ports == 'common':
            port_list = self.COMMON_PORTS
        elif ports == 'extended':
            port_list = self.EXTENDED_PORTS
        elif isinstance(ports, list):
            port_list = ports
        else:
            port_list = self.COMMON_PORTS
        
        open_ports = []
        
        # Fast SYN scan using subprocess if available
        if fast and os.geteuid() == 0:  # Root access
            open_ports = self.nmap_scan(host, port_list)
        else:
            # Fallback to socket scanning
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port 
                          for port in port_list}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
        
        # Service and version detection on open ports
        services = []
        for port in sorted(open_ports):
            service_info = self.SERVICE_FINGERPRINTS.get(port, {'name': 'unknown', 'banner_check': False})
            service_name = service_info['name']
            
            banner = None
            version = None
            
            # Grab banner if applicable
            if service_info['banner_check']:
                banner, version = self.grab_banner(ip, port, service_name)
            
            # HTTP version detection
            http_info = None
            if service_name in ['http', 'https', 'http-proxy', 'https-alt']:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{host}:{port}"
                http_info = self.http_version_check(url)
                
                if http_info and http_info.get('server'):
                    version = http_info['server']
            
            services.append({
                'port': port,
                'service': service_name,
                'version': version,
                'banner': banner[:200] if banner else None,
                'http_info': http_info
            })
        
        return {
            'host': host,
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'open_ports': open_ports,
            'services': services
        }
    
    def nmap_scan(self, host, ports):
        """Use nmap for faster scanning if available"""
        try:
            port_range = ','.join(map(str, ports[:100]))  # Limit for speed
            cmd = f"nmap -Pn -sS -T4 -p {port_range} --open {host}"
            result = subprocess.run(cmd.split(), capture_output=True, timeout=30, text=True)
            
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
            
            return open_ports
        except:
            return []


class TechnologyDetector:
    """Enhanced technology stack detection"""
    
    TECH_SIGNATURES = {
        # CMS
        'wordpress': {
            'headers': ['X-Powered-By: W3 Total Cache'],
            'body': ['wp-content', 'wp-includes', 'wordpress'],
            'meta': ['WordPress']
        },
        'drupal': {
            'headers': ['X-Generator: Drupal'],
            'body': ['sites/all/themes', 'drupal.js'],
            'meta': ['Drupal']
        },
        'joomla': {
            'body': ['joomla', '/components/com_'],
            'meta': ['Joomla']
        },
        
        # Frameworks
        'django': {
            'headers': ['X-Frame-Options: DENY'],
            'body': ['csrfmiddlewaretoken'],
            'cookies': ['csrftoken', 'sessionid']
        },
        'flask': {
            'headers': ['Server: Werkzeug'],
            'cookies': ['session']
        },
        'rails': {
            'headers': ['X-Runtime'],
            'body': ['csrf-token', 'csrf-param'],
            'cookies': ['_session_id']
        },
        'laravel': {
            'headers': ['Set-Cookie: laravel_session'],
            'cookies': ['laravel_session', 'XSRF-TOKEN']
        },
        'spring': {
            'headers': ['X-Application-Context'],
            'cookies': ['JSESSIONID']
        },
        
        # Servers
        'nginx': {
            'headers': ['Server: nginx']
        },
        'apache': {
            'headers': ['Server: Apache']
        },
        'iis': {
            'headers': ['Server: Microsoft-IIS']
        },
        
        # JS Frameworks
        'react': {
            'body': ['react', '_reactRoot', 'data-reactid']
        },
        'vue': {
            'body': ['data-v-', '__vue__']
        },
        'angular': {
            'body': ['ng-app', 'ng-controller', 'angular.js']
        },
        
        # Cloud & CDN
        'cloudflare': {
            'headers': ['Server: cloudflare', 'CF-RAY']
        },
        'aws': {
            'headers': ['X-Amz-', 'X-Amzn-']
        },
        'google-cloud': {
            'headers': ['X-Cloud-Trace-Context', 'X-Goog-']
        },
        'azure': {
            'headers': ['X-Azure-', 'X-Ms-']
        },
        
        # Databases & Caching
        'mysql': {
            'error_messages': ['mysql', 'sql syntax']
        },
        'postgresql': {
            'error_messages': ['postgresql', 'psql']
        },
        'mongodb': {
            'error_messages': ['mongodb', 'mongo']
        },
        'redis': {
            'ports': [6379]
        }
    }
    
    def detect(self, url, response=None, scan_result=None):
        """Detect technologies from URL, response, and port scan"""
        detected = set()
        
        # HTTP-based detection
        if response:
            # Check headers
            for tech, sigs in self.TECH_SIGNATURES.items():
                if 'headers' in sigs:
                    for header_sig in sigs['headers']:
                        for header, value in response.headers.items():
                            if header_sig.lower() in f"{header}: {value}".lower():
                                detected.add(tech)
                
                # Check body
                if 'body' in sigs and response.text:
                    for body_sig in sigs['body']:
                        if body_sig.lower() in response.text.lower():
                            detected.add(tech)
                
                # Check cookies
                if 'cookies' in sigs:
                    for cookie_name in sigs['cookies']:
                        if cookie_name in response.cookies:
                            detected.add(tech)
        
        # Port-based detection
        if scan_result and 'services' in scan_result:
            for service in scan_result['services']:
                service_name = service.get('service', '').lower()
                
                # Map service names to technologies
                tech_map = {
                    'mysql': 'mysql',
                    'postgresql': 'postgresql',
                    'mongodb': 'mongodb',
                    'redis': 'redis',
                    'elasticsearch': 'elasticsearch',
                    'ssh': 'openssh',
                    'ftp': 'ftp',
                    'smtp': 'smtp'
                }
                
                if service_name in tech_map:
                    detected.add(tech_map[service_name])
                
                # Add version info if available
                if service.get('version'):
                    detected.add(f"{service_name}-{service['version']}")
        
        return list(detected)


class DarkWxlfReporter:
    """Generate Dark Wxlf compatible reports"""
    
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_report(self, program_name, assets_data, cves_data, historical_data=None):
        """Generate comprehensive Dark Wxlf formatted report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dark_wxlf_report_{program_name.replace(' ', '_')}_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write(f"DARK WXLF RECONNAISSANCE REPORT\n")
            f.write(f"Program: {program_name}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Report ID: {hashlib.md5(filename.encode()).hexdigest()[:12]}\n")
            f.write("=" * 80 + "\n\n")
            
            # Executive Summary
            f.write("[EXECUTIVE SUMMARY]\n")
            f.write("-" * 80 + "\n")
            total_assets = len(assets_data)
            total_ports = sum(len(a.get('scan_result', {}).get('open_ports', [])) for a in assets_data)
            critical_cves = len([c for c in cves_data if c.get('cvss', 0) >= 9.0])
            high_cves = len([c for c in cves_data if 7.0 <= c.get('cvss', 0) < 9.0])
            
            f.write(f"Total Assets Discovered: {total_assets}\n")
            f.write(f"Total Open Ports: {total_ports}\n")
            f.write(f"Critical CVEs: {critical_cves}\n")
            f.write(f"High CVEs: {high_cves}\n")
            
            if historical_data:
                f.write(f"New Assets (since last scan): {historical_data.get('new_assets', 0)}\n")
                f.write(f"Changed Services: {historical_data.get('changed_services', 0)}\n")
            
            f.write("\n")
            
            # Asset Inventory
            f.write("[ASSET INVENTORY]\n")
            f.write("-" * 80 + "\n")
            for idx, asset in enumerate(assets_data, 1):
                url = asset.get('url', 'N/A')
                status = asset.get('status_code', 'N/A')
                title = asset.get('title', 'N/A')
                
                f.write(f"\n[{idx}] {url}\n")
                f.write(f"    Status: {status}\n")
                f.write(f"    Title: {title}\n")
                
                # Technologies
                tech = asset.get('technologies', [])
                if tech:
                    f.write(f"    Technologies: {', '.join(tech)}\n")
                
                # Port scan results
                scan_result = asset.get('scan_result')
                if scan_result and scan_result.get('services'):
                    f.write(f"    Open Ports: {len(scan_result['open_ports'])}\n")
                    for service in scan_result['services'][:10]:  # Top 10
                        port = service['port']
                        svc_name = service['service']
                        version = service.get('version', 'unknown')
                        f.write(f"      - {port}/{svc_name} (v{version})\n")
                
                # Response headers (interesting ones)
                headers = asset.get('headers', {})
                interesting_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 
                                     'X-Generator', 'X-Frame-Options', 'Content-Security-Policy']
                for header in interesting_headers:
                    if header in headers:
                        f.write(f"    {header}: {headers[header]}\n")
            
            f.write("\n")
            
            # Technology Stack Summary
            f.write("[TECHNOLOGY STACK SUMMARY]\n")
            f.write("-" * 80 + "\n")
            all_tech = {}
            for asset in assets_data:
                for tech in asset.get('technologies', []):
                    all_tech[tech] = all_tech.get(tech, 0) + 1
            
            for tech, count in sorted(all_tech.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {tech}: {count} instance(s)\n")
            
            f.write("\n")
            
            # CVE Analysis
            f.write("[CVE ANALYSIS]\n")
            f.write("-" * 80 + "\n")
            
            if not cves_data:
                f.write("No relevant CVEs found.\n\n")
            else:
                # Group by severity
                critical = [c for c in cves_data if c.get('cvss', 0) >= 9.0]
                high = [c for c in cves_data if 7.0 <= c.get('cvss', 0) < 9.0]
                medium = [c for c in cves_data if 5.0 <= c.get('cvss', 0) < 7.0]
                
                if critical:
                    f.write("\n[CRITICAL - CVSS >= 9.0]\n")
                    for cve in critical:
                        f.write(f"\n  {cve['id']} (CVSS: {cve.get('cvss', 'N/A')})\n")
                        f.write(f"  Technologies: {', '.join(cve.get('techs', []))}\n")
                        f.write(f"  Exploit Available: {'YES' if cve.get('has_exploit') else 'NO'}\n")
                        f.write(f"  Summary: {cve.get('summary', 'N/A')[:200]}...\n")
                        f.write(f"  Published: {cve.get('published', 'N/A')}\n")
                
                if high:
                    f.write("\n[HIGH - CVSS 7.0-8.9]\n")
                    for cve in high:
                        f.write(f"\n  {cve['id']} (CVSS: {cve.get('cvss', 'N/A')})\n")
                        f.write(f"  Technologies: {', '.join(cve.get('techs', []))}\n")
                        f.write(f"  Exploit Available: {'YES' if cve.get('has_exploit') else 'NO'}\n")
                
                if medium:
                    f.write(f"\n[MEDIUM - CVSS 5.0-6.9] ({len(medium)} CVEs)\n")
                    for cve in medium[:5]:  # Show first 5
                        f.write(f"  - {cve['id']} (CVSS: {cve.get('cvss')})\n")
            
            f.write("\n")
            
            # Attack Surface Summary
            f.write("[ATTACK SURFACE SUMMARY]\n")
            f.write("-" * 80 + "\n")
            
            # Service exposure
            all_services = {}
            for asset in assets_data:
                scan = asset.get('scan_result')
                if scan and 'services' in scan:
                    for svc in scan['services']:
                        svc_name = svc['service']
                        all_services[svc_name] = all_services.get(svc_name, 0) + 1
            
            if all_services:
                f.write("Exposed Services:\n")
                for svc, count in sorted(all_services.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  - {svc}: {count} instance(s)\n")
            
            f.write("\n")
            
            # High-value targets
            f.write("[HIGH-VALUE TARGETS]\n")
            f.write("-" * 80 + "\n")
            
            # Identify interesting assets
            hvt = []
            for asset in assets_data:
                score = 0
                reasons = []
                
                # Admin panels
                url = asset.get('url', '').lower()
                if any(x in url for x in ['admin', 'login', 'portal', 'console', 'dashboard']):
                    score += 3
                    reasons.append("Admin/login interface")
                
                # Interesting technologies
                tech = asset.get('technologies', [])
                risky_tech = ['jenkins', 'gitlab', 'grafana', 'kibana', 'phpmyadmin']
                for t in risky_tech:
                    if any(t in x.lower() for x in tech):
                        score += 2
                        reasons.append(f"Running {t}")
                
                # Open interesting ports
                scan = asset.get('scan_result')
                if scan:
                    interesting_ports = [22, 3306, 5432, 6379, 9200, 27017]
                    for port in interesting_ports:
                        if port in scan.get('open_ports', []):
                            score += 1
                            reasons.append(f"Port {port} open")
                
                if score >= 2:
                    hvt.append({
                        'asset': asset,
                        'score': score,
                        'reasons': reasons
                    })
            
            for target in sorted(hvt, key=lambda x: x['score'], reverse=True)[:10]:
                f.write(f"\n{target['asset']['url']} (Score: {target['score']})\n")
                for reason in target['reasons']:
                    f.write(f"  - {reason}\n")
            
            f.write("\n")
            
            # Recommendations
            f.write("[RECOMMENDATIONS]\n")
            f.write("-" * 80 + "\n")
            
            recommendations = []
            
            # CVE-based
            if critical_cves > 0:
                recommendations.append(f"URGENT: Patch {critical_cves} critical CVEs immediately")
            if high_cves > 0:
                recommendations.append(f"HIGH: Address {high_cves} high-severity CVEs")
            
            # Service exposure
            exposed_db = ['mysql', 'postgresql', 'mongodb', 'redis']
            for db in exposed_db:
                if db in all_services:
                    recommendations.append(f"Secure exposed {db.upper()} instances ({all_services[db]} found)")
            
            # Missing security headers
            missing_headers_count = 0
            for asset in assets_data:
                headers = asset.get('headers', {})
                if 'X-Frame-Options' not in headers:
                    missing_headers_count += 1
            
            if missing_headers_count > len(assets_data) * 0.5:
                recommendations.append(f"Implement security headers (missing on {missing_headers_count} assets)")
            
            if not recommendations:
                recommendations.append("No critical issues identified - continue monitoring")
            
            for idx, rec in enumerate(recommendations, 1):
                f.write(f"{idx}. {rec}\n")
            
            f.write("\n")
            
            # Footer
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        return filepath


class HealthMonitor:
    """System health and metrics monitoring"""
    
    def __init__(self, metrics_file="metrics.json"):
        self.metrics_file = metrics_file
        self.metrics = {
            'uptime_start': datetime.now().isoformat(),
            'total_scans': 0,
            'total_assets_found': 0,
            'total_cves_found': 0,
            'total_alerts_sent': 0,
            'last_scan_time': None,
            'scan_history': [],
            'errors': []
        }
        self.load_metrics()
        
    def load_metrics(self):
        """Load metrics from file"""
        if os.path.exists(self.metrics_file):
            try:
                with open(self.metrics_file, 'r') as f:
                    saved = json.load(f)
                    self.metrics.update(saved)
            except:
                pass
    
    def save_metrics(self):
        """Save metrics to file"""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2)
        except:
            pass
    
    def record_scan(self, assets_count, cves_count):
        """Record scan completion"""
        self.metrics['total_scans'] += 1
        self.metrics['total_assets_found'] += assets_count
        self.metrics['total_cves_found'] += cves_count
        self.metrics['last_scan_time'] = datetime.now().isoformat()
        
        self.metrics['scan_history'].append({
            'timestamp': datetime.now().isoformat(),
            'assets': assets_count,
            'cves': cves_count
        })
        
        # Keep only last 100 scans
        if len(self.metrics['scan_history']) > 100:
            self.metrics['scan_history'] = self.metrics['scan_history'][-100:]
        
        self.save_metrics()
    
    def record_alert(self):
        """Record alert sent"""
        self.metrics['total_alerts_sent'] += 1
        self.save_metrics()
    
    def record_error(self, error_msg):
        """Record error"""
        self.metrics['errors'].append({
            'timestamp': datetime.now().isoformat(),
            'error': str(error_msg)
        })
        
        # Keep only last 50 errors
        if len(self.metrics['errors']) > 50:
            self.metrics['errors'] = self.metrics['errors'][-50:]
        
        self.save_metrics()
    
    def get_health_status(self):
        """Get current health status"""
        uptime_start = datetime.fromisoformat(self.metrics['uptime_start'])
        uptime = datetime.now() - uptime_start
        
        recent_errors = [e for e in self.metrics['errors'] 
                        if datetime.fromisoformat(e['timestamp']) > datetime.now() - timedelta(hours=1)]
        
        status = {
            'healthy': len(recent_errors) < 5,
            'uptime_hours': uptime.total_seconds() / 3600,
            'total_scans': self.metrics['total_scans'],
            'recent_errors': len(recent_errors),
            'last_scan': self.metrics['last_scan_time']
        }
        
        return status
    
    def export_prometheus(self):
        """Export metrics in Prometheus format"""
        lines = [
            f"# HELP lone_wxlf_uptime_seconds Time since tool started",
            f"# TYPE lone_wxlf_uptime_seconds gauge",
            f"lone_wxlf_uptime_seconds {(datetime.now() - datetime.fromisoformat(self.metrics['uptime_start'])).total_seconds()}",
            f"",
            f"# HELP lone_wxlf_scans_total Total number of scans performed",
            f"# TYPE lone_wxlf_scans_total counter",
            f"lone_wxlf_scans_total {self.metrics['total_scans']}",
            f"",
            f"# HELP lone_wxlf_assets_total Total assets discovered",
            f"# TYPE lone_wxlf_assets_total counter",
            f"lone_wxlf_assets_total {self.metrics['total_assets_found']}",
            f"",
            f"# HELP lone_wxlf_cves_total Total CVEs found",
            f"# TYPE lone_wxlf_cves_total counter",
            f"lone_wxlf_cves_total {self.metrics['total_cves_found']}",
            f"",
            f"# HELP lone_wxlf_alerts_total Total alerts sent",
            f"# TYPE lone_wxlf_alerts_total counter",
            f"lone_wxlf_alerts_total {self.metrics['total_alerts_sent']}",
        ]
        
        return '\n'.join(lines)


class CVEMonitor:
    """Enhanced CVE monitoring with exploit tracking"""
    
    def __init__(self):
        self.known_cves = set()
        self.tech_cves = defaultdict(list)
        self.last_check = None
        self.exploit_db = {}
        
    def fetch_recent_cves(self, days=7):
        """Fetch recent CVEs from multiple sources"""
        new_cves = []
        
        try:
            # Primary source: CVE CIRCL
            url = f"https://cve.circl.lu/api/last/{days}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            
            if r.status_code == 200:
                cves = r.json()
                
                for cve in cves:
                    cve_id = cve.get('id', '')
                    if cve_id and cve_id not in self.known_cves:
                        summary = cve.get('summary', '').lower()
                        cvss = cve.get('cvss', 0)
                        
                        # Filter low-severity
                        if cvss < 5.0:
                            continue
                        
                        # Technology detection
                        techs = self._detect_technologies(summary)
                        
                        if not techs:
                            continue
                        
                        # Check exploit availability
                        has_exploit = self._check_exploit_available(summary, cve_id)
                        
                        # Calculate priority
                        priority = self._calculate_priority(cvss, has_exploit)
                        
                        cve_data = {
                            'id': cve_id,
                            'summary': summary,
                            'cvss': cvss,
                            'has_exploit': has_exploit,
                            'techs': techs,
                            'priority': priority,
                            'published': cve.get('Published', '')
                        }
                        
                        new_cves.append(cve_data)
                        self.known_cves.add(cve_id)
                        
                        for tech in techs:
                            self.tech_cves[tech.lower()].append(cve_data)
                
                self.last_check = datetime.now()
                
        except Exception as e:
            pass
        
        return new_cves
    
    def _detect_technologies(self, summary):
        """Detect technologies from CVE summary"""
        techs = []
        tech_map = {
            'wordpress': ['wordpress', 'wp-admin', 'woocommerce'],
            'apache': ['apache httpd', 'apache/'],
            'nginx': ['nginx/'],
            'nodejs': ['node.js server', 'express framework'],
            'php': ['php version', 'php/'],
            'python': ['python cgi', 'cpython', 'django', 'flask'],
            'java': ['java runtime', 'openjdk', 'spring framework'],
            'ruby': ['ruby on rails', 'cruby'],
            'mysql': ['mysql server', 'mariadb server'],
            'postgresql': ['postgresql database', 'postgres server'],
            'mongodb': ['mongodb server', 'mongo database'],
            'redis': ['redis server', 'redis cache'],
            'docker': ['docker daemon', 'docker container'],
            'kubernetes': ['kubernetes cluster', 'k8s orchestrator'],
            'jenkins': ['jenkins ci', 'jenkins automation'],
            'gitlab': ['gitlab ce', 'gitlab ee'],
            'github': ['github enterprise'],
            'jira': ['jira server', 'atlassian jira'],
            'confluence': ['confluence server'],
            'grafana': ['grafana server'],
            'elasticsearch': ['elasticsearch cluster', 'elastic search'],
            'tomcat': ['apache tomcat', 'tomcat server'],
            'weblogic': ['oracle weblogic', 'weblogic server'],
            'iis': ['microsoft iis', 'internet information services']
        }
        
        for tech, keywords in tech_map.items():
            if any(kw in summary for kw in keywords):
                techs.append(tech)
        
        return techs
    
    def _check_exploit_available(self, summary, cve_id):
        """Check if public exploit is available"""
        exploit_keywords = [
            'exploit', 'poc available', 'public exploit', 
            'proof of concept', 'weaponized'
        ]
        
        return any(kw in summary.lower() for kw in exploit_keywords)
    
    def _calculate_priority(self, cvss, has_exploit):
        """Calculate priority score"""
        priority = cvss
        
        if has_exploit:
            priority += 2
        
        if cvss >= 9.0:
            priority += 1
        
        return priority
    
    def get_cves_for_tech(self, tech):
        """Get CVEs for specific technology"""
        cves = self.tech_cves.get(tech.lower(), [])
        return sorted(cves, key=lambda x: x.get('priority', 0), reverse=True)


class LoneWxlfElite:
    """Elite Bug Bounty Reconnaissance Tool"""
    
    def __init__(self):
        self.targets = []
        self.current_target = None
        
        # Safe mode settings
        self.bug_bounty_mode = False
        self.rate_limit_enabled = False
        self.max_requests_per_second = 10
        self.request_delay = 0.1
        self.last_request_time = 0
        self.rate_limit_lock = threading.Lock()
        self.total_requests = 0
        self.in_scope = []
        self.out_of_scope = []
        self.scope_enabled = False
        
        # Alert settings
        self.alerts_enabled = False
        self.discord_webhook = None
        self.telegram_bot_token = None
        self.telegram_chat_id = None
        self.alert_method = None
        
        # Daemon settings
        self.daemon_mode = False
        self.daemon_interval = 3600
        self.daemon_running = False
        
        # Alert batching
        self.pending_alerts = []
        self.last_alert_batch_time = time.time()
        
        # Database and files
        self.db_path = "lone_wxlf_elite.db"
        self.daemon_state_path = "daemon_state.pkl"
        self.pid_file = "lone_wxlf_elite.pid"
        self.log_file = "lone_wxlf_elite.log"
        self.config_file = "lone_wxlf_config.json"
        
        # State files
        self.tested_urls = set()
        self.tested_urls_file = "tested_urls.pkl"
        self.load_tested_urls()
        
        # Components
        self.cve_monitor = CVEMonitor()
        self.port_scanner = PortScanner()
        self.tech_detector = TechnologyDetector()
        self.reporter = DarkWxlfReporter()
        self.health_monitor = HealthMonitor()
        self.platform_manager = PlatformManager(self.db_path)
        
        self.init_database()
        self.load_config()
        
        # HTTP session
        self.session = requests.Session()
        self.session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Setup logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.daemon_interval = config.get('daemon_interval', 3600)
                    self.rate_limit_enabled = config.get('rate_limit_enabled', False)
                    self.max_requests_per_second = config.get('max_requests_per_second', 10)
                    self.discord_webhook = config.get('discord_webhook')
                    self.telegram_bot_token = config.get('telegram_bot_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
            except:
                pass
    
    def save_config(self):
        """Save configuration to file"""
        config = {
            'daemon_interval': self.daemon_interval,
            'rate_limit_enabled': self.rate_limit_enabled,
            'max_requests_per_second': self.max_requests_per_second,
            'discord_webhook': self.discord_webhook,
            'telegram_bot_token': self.telegram_bot_token,
            'telegram_chat_id': self.telegram_chat_id
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def reload_config(self):
        """Reload configuration without restarting"""
        self.log("Reloading configuration", "info")
        self.load_config()
        self.log("Configuration reloaded", "success")
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Programs table
        c.execute('''CREATE TABLE IF NOT EXISTS programs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      platform TEXT, 
                      handle TEXT UNIQUE, 
                      name TEXT, 
                      last_checked TEXT, 
                      scope_json TEXT,
                      added_date TEXT)''')
        
        # Assets table
        c.execute('''CREATE TABLE IF NOT EXISTS assets
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      program_handle TEXT,
                      url TEXT,
                      discovered_date TEXT,
                      last_seen TEXT,
                      status_code INTEGER,
                      title TEXT,
                      technologies TEXT,
                      scan_result TEXT,
                      UNIQUE(program_handle, url))''')
        
        # CVEs table
        c.execute('''CREATE TABLE IF NOT EXISTS cves
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      cve_id TEXT UNIQUE,
                      summary TEXT,
                      cvss REAL,
                      has_exploit INTEGER,
                      technologies TEXT,
                      priority REAL,
                      published TEXT,
                      discovered_date TEXT)''')
        
        # Scan history table
        c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      program_handle TEXT,
                      scan_date TEXT,
                      assets_found INTEGER,
                      new_assets INTEGER,
                      cves_found INTEGER)''')
        
        conn.commit()
        conn.close()
        
    def banner(self):
        """Display ASCII banner"""
        f = Figlet(font='slant')
        print(colored(f.renderText('Lone Wxlf'), 'cyan', attrs=['bold']))
        print(colored('                    ELITE EDITION', 'yellow', attrs=['bold']))
        print(colored('       Advanced Bug Bounty Reconnaissance Framework', 'white'))
        print()
        
    def log(self, message, level="info"):
        """Enhanced logging with file output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colors = {
            'info': 'cyan',
            'success': 'green',
            'warning': 'yellow',
            'error': 'red',
            'phase': 'magenta'
        }
        
        color = colors.get(level, 'white')
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[-]',
            'phase': '[>]'
        }.get(level, '[*]')
        
        formatted = f"{timestamp} {prefix} {message}"
        print(colored(formatted, color))
        
        # Also log to file
        log_level = {
            'info': logging.INFO,
            'success': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'phase': logging.INFO
        }.get(level, logging.INFO)
        
        logging.log(log_level, message)
    
    def load_tested_urls(self):
        """Load tested URLs from pickle file"""
        if os.path.exists(self.tested_urls_file):
            try:
                with open(self.tested_urls_file, 'rb') as f:
                    self.tested_urls = pickle.load(f)
            except:
                self.tested_urls = set()
    
    def save_tested_urls(self):
        """Save tested URLs to pickle file"""
        try:
            with open(self.tested_urls_file, 'wb') as f:
                pickle.dump(self.tested_urls, f)
        except:
            pass
    
    def find_subdomains(self, domain):
        """Find subdomains using multiple sources"""
        subdomains = set()
        
        # 1. crt.sh
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = requests.get(url, timeout=20, verify=False)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and '*' not in name:
                        subdomains.add(name.lower().strip())
        except:
            pass
        
        # 2. Subfinder (if available)
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                                   capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        subdomains.add(line.strip().lower())
        except:
            pass
        
        return sorted(list(subdomains))
    
    def probe_live(self, subdomains):
        """Probe subdomains for live HTTP/HTTPS"""
        live = []
        
        def check_url(subdomain):
            for proto in ['https', 'http']:
                try:
                    url = f"{proto}://{subdomain}"
                    r = self.session.get(url, timeout=5, allow_redirects=True)
                    if r.status_code:
                        return {
                            'url': url,
                            'subdomain': subdomain,
                            'status_code': r.status_code,
                            'title': self.extract_title(r.text),
                            'response': r
                        }
                except:
                    continue
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_url, sub): sub for sub in subdomains}
            
            for future in tqdm(as_completed(futures), total=len(subdomains), 
                             desc="Probing live assets", disable=len(subdomains) < 10):
                result = future.result()
                if result:
                    live.append(result)
        
        return live
    
    def extract_title(self, html):
        """Extract page title from HTML"""
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        except:
            pass
        return "No Title"
    
    def profile_asset(self, asset):
        """Comprehensive asset profiling with port scanning"""
        url = asset['url']
        subdomain = asset['subdomain']
        response = asset.get('response')
        
        self.log(f"Profiling: {subdomain}", "info")
        
        profile = {
            'url': url,
            'subdomain': subdomain,
            'status_code': asset['status_code'],
            'title': asset['title'],
            'technologies': [],
            'scan_result': None,
            'headers': {},
            'cves': []
        }
        
        # Port scanning
        try:
            scan_result = self.port_scanner.scan_host(subdomain, ports='common', fast=False)
            if scan_result:
                profile['scan_result'] = scan_result
                self.log(f"Found {len(scan_result.get('open_ports', []))} open ports", "success")
        except Exception as e:
            self.log(f"Port scan failed: {str(e)}", "warning")
        
        # Technology detection
        try:
            tech = self.tech_detector.detect(url, response, scan_result)
            profile['technologies'] = tech
            if tech:
                self.log(f"Technologies: {', '.join(tech[:5])}", "info")
        except Exception as e:
            self.log(f"Tech detection failed: {str(e)}", "warning")
        
        # Headers
        if response:
            profile['headers'] = dict(response.headers)
        
        # CVE matching
        try:
            for tech in profile['technologies']:
                cves = self.cve_monitor.get_cves_for_tech(tech)
                profile['cves'].extend(cves)
            
            if profile['cves']:
                critical = len([c for c in profile['cves'] if c.get('cvss', 0) >= 9.0])
                if critical > 0:
                    self.log(f"CRITICAL: {critical} critical CVEs found!", "error")
        except Exception as e:
            self.log(f"CVE matching failed: {str(e)}", "warning")
        
        return profile
    
    def send_alert(self, title, message):
        """Send alert via configured method"""
        self.pending_alerts.append({
            'title': title,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        # Batch alerts every 5 minutes
        if time.time() - self.last_alert_batch_time > 300:
            self.flush_alerts()
    
    def flush_alerts(self):
        """Flush pending alerts"""
        if not self.pending_alerts:
            return
        
        try:
            if self.alert_method == 'discord' and self.discord_webhook:
                self._send_discord_alerts()
            elif self.alert_method == 'telegram' and self.telegram_bot_token:
                self._send_telegram_alerts()
            
            self.health_monitor.record_alert()
        except Exception as e:
            self.log(f"Alert sending failed: {str(e)}", "error")
        
        self.pending_alerts = []
        self.last_alert_batch_time = time.time()
    
    def _send_discord_alerts(self):
        """Send batched alerts to Discord"""
        if not self.discord_webhook:
            return
        
        # Batch into single message
        content = "**Lone Wxlf Alert Batch**\n\n"
        for alert in self.pending_alerts[:10]:  # Max 10
            content += f"**{alert['title']}**\n{alert['message']}\n\n"
        
        payload = {'content': content}
        requests.post(self.discord_webhook, json=payload, timeout=10)
    
    def _send_telegram_alerts(self):
        """Send batched alerts to Telegram"""
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return
        
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        
        content = "**Lone Wxlf Alert Batch**\n\n"
        for alert in self.pending_alerts[:10]:
            content += f"**{alert['title']}**\n{alert['message']}\n\n"
        
        payload = {
            'chat_id': self.telegram_chat_id,
            'text': content,
            'parse_mode': 'Markdown'
        }
        
        requests.post(url, json=payload, timeout=10)
    
    def configure_safe_mode(self):
        """Configure safe mode settings"""
        print(colored("\n[Safe Mode Configuration]", 'yellow', attrs=['bold']))
        print()
        
        mode = input(colored("Enable bug bounty safe mode? (y/n): ", 'cyan')).lower()
        if mode == 'y':
            self.bug_bounty_mode = True
            self.rate_limit_enabled = True
            self.request_delay = 0.5
            self.log("Safe mode enabled", "success")
        
        print()
    
    def configure_alerts(self):
        """Configure alert settings"""
        print(colored("\n[Alert Configuration]", 'yellow', attrs=['bold']))
        print()
        
        enable = input(colored("Enable alerts? (y/n): ", 'cyan')).lower()
        if enable != 'y':
            return
        
        self.alerts_enabled = True
        
        print(colored("  1. Discord", 'white'))
        print(colored("  2. Telegram", 'white'))
        choice = input(colored("Select alert method (1/2): ", 'cyan'))
        
        if choice == '1':
            self.alert_method = 'discord'
            self.discord_webhook = input(colored("Discord webhook URL: ", 'cyan'))
            self.save_config()
            self.log("Discord alerts configured", "success")
        elif choice == '2':
            self.alert_method = 'telegram'
            self.telegram_bot_token = input(colored("Telegram bot token: ", 'cyan'))
            self.telegram_chat_id = input(colored("Telegram chat ID: ", 'cyan'))
            self.save_config()
            self.log("Telegram alerts configured", "success")
        
        print()
    
    def configure_daemon_mode(self):
        """Configure daemon mode"""
        print(colored("\n[Daemon Mode Configuration]", 'yellow', attrs=['bold']))
        print()
        
        enable = input(colored("Enable continuous monitoring? (y/n): ", 'cyan')).lower()
        if enable == 'y':
            self.daemon_mode = True
            
            hours = input(colored("Scan interval in hours (default 6): ", 'cyan'))
            try:
                self.daemon_interval = int(hours) * 3600
            except:
                self.daemon_interval = 21600
            
            self.save_config()
            self.log(f"Daemon mode enabled (interval: {self.daemon_interval/3600}h)", "success")
        
        print()
    
    def monitor_programs(self):
        """Load programs from database"""
        print(colored("\n[Loading Programs]", 'yellow', attrs=['bold']))
        print()
        
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT handle, name, scope_json FROM programs")
            programs = c.fetchall()
            conn.close()
            
            for handle, name, scope_json in programs:
                scope = json.loads(scope_json) if scope_json else []
                if scope:
                    domain = scope[0].replace('*.', '').replace('*', '')
                    self.targets.append({
                        'handle': handle,
                        'name': name,
                        'domain': domain,
                        'scope': scope
                    })
                    self.log(f"Loaded: {name}", "success")
        except:
            pass
        
        if not self.targets:
            self.log("No programs found - add programs first", "warning")
            self._add_program_prompt()
        else:
            print()
            print(colored("Options:", 'cyan'))
            print(colored("  1. Continue with loaded programs", 'white'))
            print(colored("  2. Add more programs", 'white'))
            print(colored("  3. Remove programs", 'white'))
            print(colored("  4. Clear all and start over", 'white'))
            
            choice = input(colored("\nSelect option (default 1): ", 'cyan')).strip()
            
            if choice == '2':
                self._add_program_prompt()
            elif choice == '3':
                self._remove_programs()
            elif choice == '4':
                confirm = input(colored("Clear all programs? (y/n): ", 'yellow')).lower()
                if confirm == 'y':
                    try:
                        conn = sqlite3.connect(self.db_path)
                        c = conn.cursor()
                        c.execute("DELETE FROM programs")
                        conn.commit()
                        conn.close()
                        self.targets = []
                        self.log("All programs removed", "success")
                        self._add_program_prompt()
                    except Exception as e:
                        self.log(f"Failed to clear programs: {str(e)}", "error")
        
        print()
    
    def _remove_programs(self):
        """Remove specific programs"""
        if not self.targets:
            self.log("No programs to remove", "warning")
            return
        
        print()
        print(colored("Current programs:", 'cyan'))
        for i, target in enumerate(self.targets, 1):
            print(colored(f"  {i}. {target['name']} ({target['domain']})", 'white'))
        print(colored(f"  {len(self.targets) + 1}. Cancel", 'white'))
        
        choice = input(colored("\nSelect program to remove: ", 'cyan')).strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(self.targets):
                target = self.targets[idx]
                confirm = input(colored(f"Remove '{target['name']}'? (y/n): ", 'yellow')).lower()
                if confirm == 'y':
                    try:
                        conn = sqlite3.connect(self.db_path)
                        c = conn.cursor()
                        c.execute("DELETE FROM programs WHERE handle = ?", (target['handle'],))
                        conn.commit()
                        conn.close()
                        self.targets.pop(idx)
                        self.log(f"Removed: {target['name']}", "success")
                        
                        if not self.targets:
                            self.log("No programs remaining", "warning")
                            self._add_program_prompt()
                    except Exception as e:
                        self.log(f"Failed to remove: {str(e)}", "error")
        print()
    
    def _add_program_prompt(self):
        """Prompt to add a program"""
        print()
        print(colored("Add programs via:", 'cyan'))
        print(colored("  1. Manual entry", 'white'))
        print(colored("  2. HackerOne sync", 'white'))
        print(colored("  3. Bugcrowd sync", 'white'))
        print(colored("  4. Skip", 'white'))
        
        choice = input(colored("\nSelect option: ", 'cyan')).strip()
        
        if choice == '1':
            name = input(colored("Program name: ", 'cyan'))
            domain = input(colored("Main domain (e.g., example.com): ", 'cyan'))
            
            try:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                scope_json = json.dumps([f"*.{domain}"])
                c.execute("INSERT INTO programs (platform, handle, name, scope_json, added_date) VALUES (?, ?, ?, ?, ?)",
                         ("manual", domain, name, scope_json, datetime.now().isoformat()))
                conn.commit()
                conn.close()
                
                self.targets.append({
                    'handle': domain,
                    'name': name,
                    'domain': domain,
                    'scope': [f"*.{domain}"]
                })
                
                self.log(f"Added: {name}", "success")
            except Exception as e:
                self.log(f"Failed to add program: {str(e)}", "error")
        
        elif choice == '2':
            print()
            print(colored("HackerOne API credentials required", 'yellow'))
            print(colored("Get them from: https://hackerone.com/settings/api_token/edit", 'cyan'))
            print()
            username = input(colored("HackerOne username: ", 'cyan')).strip()
            token = input(colored("API token: ", 'cyan')).strip()
            
            if username and token:
                self.log("Syncing HackerOne programs...", "info")
                self.platform_manager.setup_hackerone(username, token)
                programs = self.platform_manager.sync_programs()
                
                if programs:
                    self.log(f"Synced {len(programs)} programs", "success")
                    for program in programs:
                        domain = program.get('scope', [''])[0].replace('*.', '').replace('*', '')
                        if domain:
                            self.targets.append({
                                'handle': program['handle'],
                                'name': program['name'],
                                'domain': domain,
                                'scope': program['scope']
                            })
                else:
                    self.log("No programs synced", "warning")
            else:
                self.log("Credentials required", "error")
        
        elif choice == '3':
            print()
            print(colored("Note: Bugcrowd API requires authentication", 'yellow'))
            print(colored("Public programs can be scraped without login", 'cyan'))
            print()
            
            email = input(colored("Bugcrowd email (press enter to skip): ", 'cyan')).strip()
            password = input(colored("Password (press enter to skip): ", 'cyan')).strip() if email else ""
            
            self.log("Syncing Bugcrowd programs...", "info")
            if email and password:
                self.platform_manager.setup_bugcrowd(email, password)
            else:
                self.platform_manager.bugcrowd = BugcrowdAPI()
            
            programs = self.platform_manager.sync_programs()
            
            if programs:
                self.log(f"Synced {len(programs)} programs", "success")
                for program in programs:
                    domain = program.get('scope', [''])[0].replace('*.', '').replace('*', '')
                    if domain:
                        self.targets.append({
                            'handle': program['handle'],
                            'name': program['name'],
                            'domain': domain,
                            'scope': program['scope']
                        })
            else:
                self.log("No programs synced", "warning")
        
        elif choice == '4':
            pass
    
    def save_assets_to_db(self, program_handle, assets_profiles):
        """Save discovered assets to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            for profile in assets_profiles:
                c.execute("""INSERT OR REPLACE INTO assets 
                            (program_handle, url, discovered_date, last_seen, status_code, 
                             title, technologies, scan_result)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                         (program_handle,
                          profile['url'],
                          datetime.now().isoformat(),
                          datetime.now().isoformat(),
                          profile['status_code'],
                          profile['title'],
                          json.dumps(profile['technologies']),
                          json.dumps(profile['scan_result']) if profile['scan_result'] else None))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Database save failed: {str(e)}", "error")
    
    def get_historical_data(self, program_handle):
        """Get historical asset data for comparison"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Get previous assets
            c.execute("SELECT url, technologies, scan_result FROM assets WHERE program_handle = ?",
                     (program_handle,))
            previous = c.fetchall()
            
            # Get scan history
            c.execute("""SELECT scan_date, assets_found, new_assets 
                        FROM scan_history 
                        WHERE program_handle = ? 
                        ORDER BY scan_date DESC 
                        LIMIT 1""",
                     (program_handle,))
            last_scan = c.fetchone()
            
            conn.close()
            
            return {
                'previous_assets': previous,
                'last_scan': last_scan
            }
        except:
            return None
    
    def start_daemon(self):
        """Start daemon process"""
        # Check if already running
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                    # Check if process exists
                    os.kill(old_pid, 0)
                    print(colored("Daemon already running", 'yellow'))
                    return
            except (OSError, ValueError):
                # Process doesn't exist, remove stale PID file
                os.remove(self.pid_file)
        
        # Fork process
        try:
            pid = os.fork()
            if pid > 0:
                # Parent process
                print(colored(f"Daemon started (PID: {pid})", 'green'))
                print(colored(f"Logs: {self.log_file}", 'cyan'))
                sys.exit(0)
        except OSError as e:
            print(colored(f"Fork failed: {e}", 'red'))
            sys.exit(1)
        
        # Child process (daemon)
        os.chdir('/')
        os.setsid()
        os.umask(0)
        
        # Second fork
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
        
        # Write PID file
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        
        si = open(os.devnull, 'r')
        so = open(self.log_file, 'a+')
        se = open(self.log_file, 'a+')
        
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
        
        # Run daemon loop
        self.daemon_running = True
        self._daemon_loop()
    
    def stop_daemon(self):
        """Stop daemon process"""
        if not os.path.exists(self.pid_file):
            print(colored("Daemon not running", 'yellow'))
            return
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            os.kill(pid, signal.SIGTERM)
            os.remove(self.pid_file)
            print(colored("Daemon stopped", 'green'))
        except Exception as e:
            print(colored(f"Failed to stop daemon: {e}", 'red'))
    
    def daemon_status(self):
        """Check daemon status"""
        if not os.path.exists(self.pid_file):
            print(colored("Daemon not running", 'yellow'))
            return
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process exists
            os.kill(pid, 0)
            
            print(colored(f"Daemon running (PID: {pid})", 'green'))
            
            # Show health status
            health = self.health_monitor.get_health_status()
            print(colored(f"Uptime: {health['uptime_hours']:.1f} hours", 'cyan'))
            print(colored(f"Total scans: {health['total_scans']}", 'cyan'))
            print(colored(f"Last scan: {health['last_scan']}", 'cyan'))
            
            if not health['healthy']:
                print(colored(f"Recent errors: {health['recent_errors']}", 'yellow'))
            
        except OSError:
            print(colored("Daemon PID file exists but process not running", 'yellow'))
            os.remove(self.pid_file)
    
    def is_daemon_running(self):
        """Check if daemon is running"""
        if not os.path.exists(self.pid_file):
            return False
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except:
            return False
    
    def _daemon_loop(self):
        """Main daemon loop"""
        self.log("Daemon started", "success")
        
        # Load state
        monitored_assets = {}
        last_cve_count = 0
        iteration = 0
        
        if os.path.exists(self.daemon_state_path):
            try:
                with open(self.daemon_state_path, 'rb') as f:
                    state = pickle.load(f)
                    iteration = state.get('iteration', 0)
                    last_cve_count = state.get('last_cve_count', 0)
                    monitored_assets = state.get('monitored_assets', {})
            except:
                pass
        
        while self.daemon_running:
            try:
                iteration += 1
                self.log(f"Starting scan iteration {iteration}", "phase")
                
                # Check for config reload signal
                if os.path.exists('.reload_config'):
                    self.reload_config()
                    os.remove('.reload_config')
                
                # Fetch CVEs
                try:
                    new_cves = self.cve_monitor.fetch_recent_cves(days=7)
                except Exception as e:
                    self.log(f"CVE fetch failed: {str(e)}", "error")
                    self.health_monitor.record_error(str(e))
                    new_cves = []
                
                if new_cves and len(new_cves) > last_cve_count:
                    critical_cves = [c for c in new_cves if c.get('cvss', 0) >= 7.0]
                    
                    self.log(f"Found {len(new_cves)} new CVEs ({len(critical_cves)} critical)", "success")
                    
                    if self.alerts_enabled and critical_cves:
                        cve_list = '\n'.join([
                            f"- {c['id']} (CVSS: {c.get('cvss', 'N/A')}) {'[EXPLOIT]' if c.get('has_exploit') else ''} - {', '.join(c['techs'])}"
                            for c in critical_cves[:10]
                        ])
                        self.send_alert(
                            f"{len(critical_cves)} Critical CVEs",
                            f"High severity vulnerabilities:\n\n{cve_list}"
                        )
                    
                    last_cve_count = len(new_cves)
                
                # Load programs
                try:
                    with sqlite3.connect(self.db_path) as conn:
                        c = conn.cursor()
                        c.execute("SELECT handle, name, scope_json FROM programs")
                        programs = c.fetchall()
                except Exception as e:
                    self.log(f"Database error: {str(e)}", "error")
                    self.health_monitor.record_error(str(e))
                    programs = []
                
                if programs:
                    self.log(f"Monitoring {len(programs)} programs", "info")
                    
                    total_new_assets = 0
                    all_assets_profiles = []
                    all_cves = []
                    
                    for handle, name, scope_json in programs:
                        if handle not in monitored_assets:
                            monitored_assets[handle] = {'subdomains': set(), 'last_check': None}
                        
                        try:
                            scope = json.loads(scope_json) if scope_json else []
                            if scope:
                                domain = scope[0].replace('*.', '').replace('*', '')
                                
                                self.log(f"Scanning {name}", "info")
                                
                                # Find subdomains
                                current_subs = set(self.find_subdomains(domain))
                                previous_subs = monitored_assets[handle]['subdomains']
                                
                                # Detect new subdomains
                                if previous_subs:
                                    new_subs = current_subs - previous_subs
                                    
                                    if new_subs:
                                        self.log(f"Found {len(new_subs)} new subdomains for {name}", "success")
                                        total_new_assets += len(new_subs)
                                        
                                        # Probe and profile new assets
                                        live_assets = self.probe_live(list(new_subs))
                                        
                                        if live_assets:
                                            profiles = []
                                            for asset in live_assets[:10]:  # Limit for performance
                                                profile = self.profile_asset(asset)
                                                profiles.append(profile)
                                                all_assets_profiles.append(profile)
                                                
                                                # Collect CVEs
                                                all_cves.extend(profile['cves'])
                                            
                                            # Save to database
                                            self.save_assets_to_db(handle, profiles)
                                            
                                            # Alert
                                            if self.alerts_enabled:
                                                sub_list = '\n'.join([f"- {sub}" for sub in list(new_subs)[:10]])
                                                self.send_alert(
                                                    f"New Assets: {name}",
                                                    f"Discovered {len(new_subs)} new subdomains:\n\n{sub_list}\n\nProfiles saved to database."
                                                )
                                
                                monitored_assets[handle]['subdomains'] = current_subs
                                monitored_assets[handle]['last_check'] = datetime.now().isoformat()
                                
                                # Record scan in history
                                with sqlite3.connect(self.db_path) as conn:
                                    c = conn.cursor()
                                    c.execute("""INSERT INTO scan_history 
                                                (program_handle, scan_date, assets_found, new_assets, cves_found)
                                                VALUES (?, ?, ?, ?, ?)""",
                                             (handle, datetime.now().isoformat(), 
                                              len(current_subs), len(new_subs) if previous_subs else 0, 
                                              len(all_cves)))
                                    conn.commit()
                        
                        except Exception as e:
                            self.log(f"Error monitoring {name}: {str(e)}", "error")
                            self.health_monitor.record_error(f"{name}: {str(e)}")
                            continue
                    
                    # Generate Dark Wxlf report if new assets found
                    if all_assets_profiles:
                        for handle, name, _ in programs:
                            program_profiles = [p for p in all_assets_profiles 
                                              if any(handle in p['url'] for _ in [1])]
                            if program_profiles:
                                historical = self.get_historical_data(handle)
                                report_path = self.reporter.generate_report(
                                    name,
                                    program_profiles,
                                    all_cves,
                                    historical
                                )
                                self.log(f"Dark Wxlf report generated: {report_path}", "success")
                    
                    # Record metrics
                    self.health_monitor.record_scan(total_new_assets, len(all_cves))
                    
                else:
                    self.log("No programs to monitor", "warning")
                
                # Save state
                try:
                    state = {
                        'iteration': iteration,
                        'last_cve_count': last_cve_count,
                        'monitored_assets': monitored_assets
                    }
                    with open(self.daemon_state_path, 'wb') as f:
                        pickle.dump(state, f)
                except Exception as e:
                    self.log(f"Failed to save state: {str(e)}", "warning")
                
                # Flush alerts
                self.flush_alerts()
                
                # Wait for next iteration
                hours = self.daemon_interval / 3600
                self.log(f"Next check in {hours:.0f}h", "info")
                
                time.sleep(self.daemon_interval)
                
            except KeyboardInterrupt:
                self.daemon_running = False
                self.log("Daemon stopped", "warning")
                break
            except Exception as e:
                self.log(f"Daemon error: {str(e)}", "error")
                self.health_monitor.record_error(str(e))
                time.sleep(60)
    
    def run(self):
        """Main execution flow"""
        self.banner()
        
        # Configuration
        self.configure_safe_mode()
        self.configure_alerts()
        self.configure_daemon_mode()
        
        if self.daemon_mode:
            print()
            print(colored("Daemon mode will run in background", 'green'))
            print(colored("Use: python3 lone_wxlf_elite.py --daemon start", 'white'))
            print()
        
        # Load programs (will keep prompting until we have targets)
        while not self.targets:
            self.monitor_programs()
            if not self.targets:
                retry = input(colored("\nNo targets loaded. Try again? (y/n): ", 'yellow')).lower()
                if retry != 'y':
                    self.log("Exiting - no targets", "warning")
                    return
        
        print()
        print(colored(f"Loaded {len(self.targets)} target(s)", 'green', attrs=['bold']))
        for i, t in enumerate(self.targets, 1):
            print(colored(f"  {i}. {t.get('name', 'Unknown')}", 'green'))
        print()
        
        # Initial reconnaissance
        self.log("Starting elite reconnaissance", "phase")
        
        for target in self.targets:
            domain = target.get('domain', target.get('handle', ''))
            self.log(f"\nTarget: {target.get('name')}", "phase")
            
            # Subdomain discovery
            self.log("Discovering subdomains", "info")
            subs = self.find_subdomains(domain)
            self.log(f"Found {len(subs)} subdomains", "success")
            
            # Probe live
            self.log("Probing live assets", "info")
            live = self.probe_live(subs)
            
            if not live:
                self.log("No live assets found", "warning")
                continue
            
            self.log(f"Found {len(live)} live assets", "success")
            
            # Profile assets
            self.log("Profiling assets (scanning ports & detecting tech)", "info")
            profiles = []
            all_cves = []
            
            for asset in tqdm(live[:20], desc="Profiling"):  # Limit to 20 for initial scan
                profile = self.profile_asset(asset)
                profiles.append(profile)
                all_cves.extend(profile['cves'])
            
            # Save to database
            self.save_assets_to_db(target['handle'], profiles)
            
            # Generate Dark Wxlf report
            self.log("Generating Dark Wxlf report", "info")
            historical = self.get_historical_data(target['handle'])
            report_path = self.reporter.generate_report(
                target['name'],
                profiles,
                all_cves,
                historical
            )
            
            print()
            print(colored(f"✓ Report generated: {report_path}", 'green', attrs=['bold']))
            print()
            
            # Summary
            critical_cves = len([c for c in all_cves if c.get('cvss', 0) >= 9.0])
            if critical_cves > 0:
                self.log(f"⚠ Found {critical_cves} CRITICAL CVEs!", "error")
        
        print()
        self.log("Elite reconnaissance complete", "success")
        print()
        
        # Health status
        health = self.health_monitor.get_health_status()
        print(colored(f"Health Status: {'✓ Healthy' if health['healthy'] else '⚠ Issues detected'}", 
                     'green' if health['healthy'] else 'yellow'))
        print(colored(f"Total scans: {health['total_scans']}", 'cyan'))
        print()
        
        if self.daemon_mode:
            print(colored("To start continuous monitoring:", 'cyan'))
            print(colored("  python3 lone_wxlf_elite.py --daemon start", 'white'))
            print()


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        tool = LoneWxlfElite()
        
        if sys.argv[1] == '--daemon':
            if len(sys.argv) < 3:
                print("Usage: python3 lone_wxlf_elite.py --daemon [start|stop|status|reload]")
                sys.exit(1)
            
            cmd = sys.argv[2]
            
            if cmd == 'start':
                if tool.is_daemon_running():
                    print(colored("Daemon already running", 'yellow'))
                    sys.exit(1)
                
                print(colored("Starting daemon...", 'green'))
                tool.configure_safe_mode()
                tool.configure_alerts()
                tool.daemon_mode = True
                tool.daemon_interval = 21600  # 6 hours
                
                tool.start_daemon()
            
            elif cmd == 'stop':
                tool.stop_daemon()
            
            elif cmd == 'status':
                tool.daemon_status()
            
            elif cmd == 'reload':
                # Signal daemon to reload config
                Path('.reload_config').touch()
                print(colored("Configuration reload signal sent", 'green'))
            
            else:
                print("Unknown command. Use: start, stop, status, or reload")
                sys.exit(1)
            
            sys.exit(0)
        
        elif sys.argv[1] == '--metrics':
            # Export Prometheus metrics
            tool = LoneWxlfElite()
            print(tool.health_monitor.export_prometheus())
            sys.exit(0)
    
    try:
        tool = LoneWxlfElite()
        tool.run()
    except KeyboardInterrupt:
        print(colored("\n\nStopped", 'yellow'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\nFatal error: {str(e)}", 'red'))
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
