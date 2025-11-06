#!/usr/bin/env python3
"""
AI Recon Tool - A comprehensive reconnaissance tool for security testing
Features: Port Scanning, Web Scraping, Subdomain Enumeration
"""

import socket
import argparse
import requests
from bs4 import BeautifulSoup
import concurrent.futures
from urllib.parse import urljoin, urlparse
import sys
import time
from typing import List, Set
import re


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class PortScanner:
    """Port scanning functionality"""
    
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
    
    def scan_port(self, port: int) -> tuple:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return (port, result == 0)
        except Exception as e:
            return (port, False)
    
    def scan_range(self, start_port: int, end_port: int, max_workers: int = 100) -> List[tuple]:
        """Scan a range of ports"""
        print(f"{Colors.CYAN}[*] Scanning ports {start_port}-{end_port} on {self.target}...{Colors.RESET}")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start_port, end_port + 1)}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = self.common_ports.get(port, 'Unknown')
                    open_ports.append((port, service))
                    print(f"{Colors.GREEN}[+] Port {port} is open ({service}){Colors.RESET}")
        
        return open_ports
    
    def scan_common_ports(self, max_workers: int = 100) -> List[tuple]:
        """Scan common ports"""
        print(f"{Colors.CYAN}[*] Scanning common ports on {self.target}...{Colors.RESET}")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in self.common_ports.keys()}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = self.common_ports.get(port, 'Unknown')
                    open_ports.append((port, service))
                    print(f"{Colors.GREEN}[+] Port {port} is open ({service}){Colors.RESET}")
        
        return open_ports


class WebScraper:
    """Web scraping functionality"""
    
    def __init__(self, url: str, timeout: int = 10):
        self.url = url if url.startswith(('http://', 'https://')) else f'https://{url}'
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_page_content(self) -> dict:
        """Scrape basic page information"""
        try:
            print(f"{Colors.CYAN}[*] Scraping {self.url}...{Colors.RESET}")
            response = self.session.get(self.url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract title
            title = soup.find('title')
            title_text = title.string if title else 'No title found'
            
            # Extract meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            description = meta_desc.get('content', 'No description') if meta_desc else 'No description'
            
            # Extract all links
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(self.url, href)
                links.append({
                    'text': link.get_text(strip=True)[:50],
                    'url': absolute_url
                })
            
            # Extract forms
            forms = []
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET')
                form_inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_inputs.append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'placeholder': input_tag.get('placeholder', '')
                    })
                forms.append({
                    'action': urljoin(self.url, action),
                    'method': method,
                    'inputs': form_inputs
                })
            
            # Extract images
            images = []
            for img in soup.find_all('img', src=True):
                src = img['src']
                absolute_url = urljoin(self.url, src)
                images.append({
                    'alt': img.get('alt', 'No alt text'),
                    'src': absolute_url
                })
            
            # Extract scripts
            scripts = []
            for script in soup.find_all('script', src=True):
                scripts.append(urljoin(self.url, script['src']))
            
            # Extract headers
            headers_info = dict(response.headers)
            
            result = {
                'url': self.url,
                'status_code': response.status_code,
                'title': title_text,
                'description': description,
                'headers': headers_info,
                'links_count': len(links),
                'links': links[:20],  # Limit to first 20
                'forms_count': len(forms),
                'forms': forms,
                'images_count': len(images),
                'images': images[:10],  # Limit to first 10
                'scripts_count': len(scripts),
                'scripts': scripts[:10]  # Limit to first 10
            }
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[-] Error scraping {self.url}: {str(e)}{Colors.RESET}")
            return None
    
    def print_results(self, data: dict):
        """Print scraping results in a formatted way"""
        if not data:
            return
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}Web Scraping Results{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        print(f"{Colors.GREEN}URL:{Colors.RESET} {data['url']}")
        print(f"{Colors.GREEN}Status Code:{Colors.RESET} {data['status_code']}")
        print(f"{Colors.GREEN}Title:{Colors.RESET} {data['title']}")
        print(f"{Colors.GREEN}Description:{Colors.RESET} {data['description']}\n")
        
        print(f"{Colors.YELLOW}Headers:{Colors.RESET}")
        for key, value in list(data['headers'].items())[:10]:
            print(f"  {key}: {value}")
        
        print(f"\n{Colors.YELLOW}Links Found ({data['links_count']}):{Colors.RESET}")
        for link in data['links']:
            print(f"  - {link['text']} -> {link['url']}")
        
        print(f"\n{Colors.YELLOW}Forms Found ({data['forms_count']}):{Colors.RESET}")
        for i, form in enumerate(data['forms'], 1):
            print(f"  Form {i}:")
            print(f"    Action: {form['action']}")
            print(f"    Method: {form['method']}")
            print(f"    Inputs: {len(form['inputs'])}")
            for inp in form['inputs'][:5]:
                print(f"      - {inp['name']} ({inp['type']})")
        
        print(f"\n{Colors.YELLOW}Images Found ({data['images_count']}):{Colors.RESET}")
        for img in data['images']:
            print(f"  - {img['alt']}: {img['src']}")
        
        print(f"\n{Colors.YELLOW}Scripts Found ({data['scripts_count']}):{Colors.RESET}")
        for script in data['scripts']:
            print(f"  - {script}")


class SubdomainEnumerator:
    """Subdomain enumeration functionality"""
    
    def __init__(self, domain: str, timeout: float = 2.0):
        self.domain = domain.strip()
        if self.domain.startswith(('http://', 'https://')):
            self.domain = urlparse(self.domain).netloc
        self.timeout = timeout
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
            'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
            'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'web', 'mbx', 'shop', 'svn', 'sip', 'dns2', 'api', 'cdn', 'stats',
            'dns1', 'www1', 'ftp2', 'demo', 'mx1', 'chat', 'www3', 'dev2',
            'smtp2', 'biz', 'server1', 'smtp1', 'test2', 'ns4', 'www4',
            'panel', 'git', 'portal', 'ai', 'cloud', 'app', 'auth', 'api2',
            'staging', 'secure', 'vps', 'www5', 'www6', 'www7', 'www8'
        ]
    
    def check_subdomain(self, subdomain: str) -> tuple:
        """Check if a subdomain exists"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            # Try DNS resolution
            socket.gethostbyname(full_domain)
            return (full_domain, True)
        except socket.gaierror:
            return (full_domain, False)
        except Exception:
            return (full_domain, False)
    
    def enumerate_common(self, max_workers: int = 50) -> List[str]:
        """Enumerate common subdomains"""
        print(f"{Colors.CYAN}[*] Enumerating common subdomains for {self.domain}...{Colors.RESET}")
        found_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.check_subdomain, subdomain): subdomain 
                      for subdomain in self.common_subdomains}
            
            for future in concurrent.futures.as_completed(futures):
                subdomain, exists = future.result()
                if exists:
                    found_subdomains.append(subdomain)
                    print(f"{Colors.GREEN}[+] Found: {subdomain}{Colors.RESET}")
        
        return found_subdomains
    
    def enumerate_from_file(self, wordlist_file: str, max_workers: int = 50) -> List[str]:
        """Enumerate subdomains from a wordlist file"""
        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[-] Wordlist file not found: {wordlist_file}{Colors.RESET}")
            return []
        
        print(f"{Colors.CYAN}[*] Enumerating subdomains from {wordlist_file} for {self.domain}...{Colors.RESET}")
        found_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.check_subdomain, subdomain): subdomain 
                      for subdomain in wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                subdomain, exists = future.result()
                if exists:
                    found_subdomains.append(subdomain)
                    print(f"{Colors.GREEN}[+] Found: {subdomain}{Colors.RESET}")
        
        return found_subdomains


def main():
    parser = argparse.ArgumentParser(
        description='AI Recon Tool - Port Scanning, Web Scraping, and Subdomain Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Port scan common ports
  python recon_tool.py --port-scan example.com
  
  # Port scan specific range
  python recon_tool.py --port-scan example.com --port-range 1 1000
  
  # Web scraping
  python recon_tool.py --web-scrape example.com
  
  # Subdomain enumeration
  python recon_tool.py --subdomain-enum example.com
  
  # Subdomain enumeration with wordlist
  python recon_tool.py --subdomain-enum example.com --wordlist subdomains.txt
        """
    )
    
    parser.add_argument('--port-scan', dest='port_scan', metavar='TARGET',
                       help='Target hostname or IP address for port scanning')
    parser.add_argument('--port-range', nargs=2, type=int, metavar=('START', 'END'),
                       help='Port range to scan (default: common ports only)')
    parser.add_argument('--web-scrape', dest='web_scrape', metavar='URL',
                       help='URL or domain to scrape')
    parser.add_argument('--subdomain-enum', dest='subdomain_enum', metavar='DOMAIN',
                       help='Domain for subdomain enumeration')
    parser.add_argument('--wordlist', metavar='FILE',
                       help='Wordlist file for subdomain enumeration')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Timeout for network operations (default: 2.0)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for concurrent operations (default: 50)')
    
    args = parser.parse_args()
    
    # Suppress SSL warnings for web scraping
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if not any([args.port_scan, args.web_scrape, args.subdomain_enum]):
        parser.print_help()
        return
    
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}AI Recon Tool{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    # Port Scanning
    if args.port_scan:
        scanner = PortScanner(args.port_scan, timeout=args.timeout)
        if args.port_range:
            start_port, end_port = args.port_range
            open_ports = scanner.scan_range(start_port, end_port, max_workers=args.threads)
        else:
            open_ports = scanner.scan_common_ports(max_workers=args.threads)
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}Scan Summary:{Colors.RESET}")
        print(f"{Colors.GREEN}Found {len(open_ports)} open port(s){Colors.RESET}")
        for port, service in open_ports:
            print(f"  - Port {port}: {service}")
    
    # Web Scraping
    if args.web_scrape:
        scraper = WebScraper(args.web_scrape, timeout=int(args.timeout * 5))
        results = scraper.get_page_content()
        scraper.print_results(results)
    
    # Subdomain Enumeration
    if args.subdomain_enum:
        enumerator = SubdomainEnumerator(args.subdomain_enum, timeout=args.timeout)
        if args.wordlist:
            found_subdomains = enumerator.enumerate_from_file(args.wordlist, max_workers=args.threads)
        else:
            found_subdomains = enumerator.enumerate_common(max_workers=args.threads)
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}Enumeration Summary:{Colors.RESET}")
        print(f"{Colors.GREEN}Found {len(found_subdomains)} subdomain(s){Colors.RESET}")
        for subdomain in found_subdomains:
            print(f"  - {subdomain}")
    
    print(f"\n{Colors.CYAN}[*] Reconnaissance complete!{Colors.RESET}\n")


if __name__ == '__main__':
    main()

