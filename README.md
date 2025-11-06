# Simple Recon Tool

A comprehensive Python reconnaissance tool for security testing and information gathering. This tool performs port scanning, web scraping, and subdomain enumeration.

## Features

- **Port Scanning**: Scan common ports or custom port ranges on target hosts
- **Web Scraping**: Extract information from websites including links, forms, images, and metadata
- **Subdomain Enumeration**: Discover subdomains using common wordlists or custom wordlists

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Port Scanning

Scan common ports on a target:
```bash
python recon_tool.py --port-scan example.com
```

Scan a specific port range:
```bash
python recon_tool.py --port-scan example.com --port-range 1 1000
```

### Web Scraping

Scrape a website:
```bash
python recon_tool.py --web-scrape https://example.com
```

Or just provide a domain (will use HTTPS):
```bash
python recon_tool.py --web-scrape example.com
```

### Subdomain Enumeration

Enumerate common subdomains:
```bash
python recon_tool.py --subdomain-enum example.com
```

Use a custom wordlist:
```bash
python recon_tool.py --subdomain-enum example.com --wordlist subdomains.txt
```

### Advanced Options

- `--timeout`: Set timeout for network operations (default: 2.0 seconds)
- `--threads`: Set number of concurrent threads (default: 50)

Example with custom settings:
```bash
python recon_tool.py --port-scan example.com --timeout 3.0 --threads 100
```

## Examples

Run multiple operations:
```bash
# Port scan
python recon_tool.py --port-scan target.com

# Web scrape
python recon_tool.py --web-scrape target.com

# Subdomain enumeration
python recon_tool.py --subdomain-enum target.com
```

## Legal Notice

This tool is for authorized security testing only. Always ensure you have permission before scanning or enumerating any target. Unauthorized access to computer systems is illegal.

## License

This tool is provided as-is for educational and authorized security testing purposes.


