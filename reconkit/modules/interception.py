import json, requests, platform, subprocess
from urllib.parse import urlparse
from requests.models import PreparedRequest, Response
from typing import Optional, List, Dict, Union, Tuple, Callable
from colorama import init, Fore
from dataclasses import dataclass
import re

init(autoreset=True)

@dataclass
class TrafficRule:
    pattern: str
    action: str  # 'modify', 'block', 'redirect'
    replacement: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    status_code: Optional[int] = None

class HttpInterceptor:
    def __init__(
        self,
        url_contains: Optional[str] = None,
        status_codes: Optional[List[int]] = None,
        max_body_length: int = 500,
        sensitive_headers: List[str] = ["Authorization", "Cookie"],
        log_file: Optional[str] = None,
        methods: Optional[List[str]] = None,
        rules: Optional[List[TrafficRule]] = None,
        edit_callback: Optional[Callable] = None
    ):
        """Enhanced HTTP interceptor with traffic modification capabilities.
        
        Args:
            url_contains: Substring to match in URLs
            status_codes: List of status codes to log
            max_body_length: Maximum characters to log from body content
            sensitive_headers: Headers to redact from logs
            log_file: Path to file for logging (None for stdout)
            methods: HTTP methods to log (None for all)
            rules: List of TrafficRule objects for modifying traffic
            edit_callback: Callback function for manual request editing
        """
        self.filters = {
            "url_contains": url_contains,
            "status_codes": status_codes,
            "methods": methods
        }
        self.max_body_length = max_body_length
        self.sensitive_headers = [h.lower() for h in sensitive_headers]
        self.log_file = log_file
        self.rules = rules or []
        self.edit_callback = edit_callback
        self.active_interceptions = {}

    def add_rule(self, rule: TrafficRule) -> None:
        """Add a new traffic modification rule."""
        self.rules.append(rule)

    def clear_rules(self) -> None:
        """Clear all traffic modification rules."""
        self.rules = []

    def set_filters(
        self,
        url_contains: Optional[str] = None,
        status_codes: Optional[List[int]] = None,
        methods: Optional[List[str]] = None
    ) -> None:
        """Update the active filters."""
        self.filters.update({
            "url_contains": url_contains,
            "status_codes": status_codes,
            "methods": methods
        })

    def _apply_rules(self, req: PreparedRequest) -> Tuple[bool, Optional[PreparedRequest]]:
        """Apply traffic rules to the request."""
        modified = False
        new_req = req
        
        for rule in self.rules:
            if re.search(rule.pattern, req.url):
                if rule.action == 'block':
                    return True, None
                elif rule.action == 'redirect' and rule.replacement:
                    new_req = self._clone_request(req)
                    new_req.url = re.sub(rule.pattern, rule.replacement, req.url)
                    modified = True
                elif rule.action == 'modify':
                    new_req = self._clone_request(req)
                    if rule.headers:
                        new_req.headers.update(rule.headers)
                    if rule.replacement and req.body:
                        try:
                            body = json.loads(req.body)
                            modified_body = re.sub(rule.pattern, rule.replacement, json.dumps(body))
                            new_req.body = modified_body
                        except json.JSONDecodeError:
                            new_req.body = re.sub(rule.pattern, rule.replacement, req.body)
                    modified = True
        
        # Apply callback if provided
        if self.edit_callback:
            try:
                result = self.edit_callback(new_req)
                if result is not None:
                    return True, result if isinstance(result, PreparedRequest) else new_req
            except Exception as e:
                print(Fore.RED + f"Callback error: {e}")
        
        return modified, new_req

    def _clone_request(self, req: PreparedRequest) -> PreparedRequest:
        """Create a deep copy of a request."""
        new_req = PreparedRequest()
        new_req.method = req.method
        new_req.url = req.url
        new_req.headers = req.headers.copy()
        new_req.body = req.body
        new_req.hooks = req.hooks.copy()
        return new_req

    def _should_log(self, req: PreparedRequest, resp: Optional[Response] = None) -> bool:
        """Determine if the request/response should be logged based on filters."""
        # Check URL filter
        if self.filters["url_contains"]:
            try:
                if not re.search(self.filters["url_contains"], req.url):
                    return False
            except re.error:
                if self.filters["url_contains"] not in req.url:
                    return False
                    
        # Check method filter
        if self.filters["methods"] and req.method.upper() not in [m.upper() for m in self.filters["methods"]]:
            return False
            
        # Check status code filter (only applicable if response exists)
        if resp and self.filters["status_codes"] and resp.status_code not in self.filters["status_codes"]:
            return False
            
        return True

    def _redact_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive headers from the log output."""
        return {
            k: "[REDACTED]" if k.lower() in self.sensitive_headers else v
            for k, v in headers.items()
        }

    def _pretty_content(self, content: Union[str, bytes]) -> str:
        """Format content as pretty JSON if possible, otherwise return as text."""
        if not content:
            return ""
            
        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            parsed = json.loads(content)
            pretty = json.dumps(parsed, indent=2)
            return pretty[:self.max_body_length]
        except (json.JSONDecodeError, UnicodeDecodeError):
            return str(content)[:self.max_body_length]

    def _write_log(self, message: str) -> None:
        """Write log message to configured output."""
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
        else:
            print(message)

    def intercept_request(self, req: PreparedRequest) -> Optional[PreparedRequest]:
        """Intercept and potentially modify a request before sending."""
        # Apply traffic rules
        should_block, modified_req = self._apply_rules(req)
        if should_block and modified_req is None:
            print(Fore.YELLOW + f"Blocked request to {req.url}")
            return None
            
        if modified_req is not req:
            print(Fore.CYAN + f"Modified request to {modified_req.url}")
            req = modified_req
        
        # Store original request for response correlation
        self.active_interceptions[id(req)] = req.copy()
        
        return req

    def intercept_response(self, req: PreparedRequest, resp: Response) -> Optional[Response]:
        """Intercept and potentially modify a response before processing."""
        # Check if we have the original request
        if id(req) not in self.active_interceptions:
            return resp
            
        original_req = self.active_interceptions.pop(id(req))
        
        # Apply response modifications here if needed
        # (similar to request interception logic)
        
        self.log_traffic(original_req, resp)
        return resp

    def log_traffic(self, req: PreparedRequest, resp: Optional[Response] = None) -> None:
        """Log HTTP traffic according to configured filters and options."""
        if not self._should_log(req, resp):
            return

        log_lines = []
        divider = "=" * 60
        
        # Request info
        log_lines.append(divider)
        log_lines.append(f"[HTTP] {req.method} {req.url}")
        
        # Request headers (redacted)
        redacted_headers = self._redact_sensitive_headers(dict(req.headers))
        for k, v in redacted_headers.items():
            log_lines.append(f"  > {k}: {v}")
            
        # Request body
        if req.body:
            log_lines.append(f"  > Body:\n{self._pretty_content(req.body)}")

        # Response info (if available)
        if resp:
            log_lines.append(f"\n[RESP] Status: {resp.status_code}")
            
            # Response headers (redacted)
            redacted_resp_headers = self._redact_sensitive_headers(dict(resp.headers))
            for k, v in redacted_resp_headers.items():
                log_lines.append(f"  < {k}: {v}")
                
            # Response body
            if resp.content:
                log_lines.append(f"  < Body:\n{self._pretty_content(resp.content)}")
        
        log_lines.append(divider + "\n")
        
        # Write complete log
        self._write_log('\n'.join(log_lines))


def configure_system_proxy(port: int = 8080):
    """Attempt to configure system proxy settings automatically."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["netsh", "winhttp", "set", "proxy", f"localhost:{port}"])
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["networksetup", "-setwebproxy", "Wi-Fi", "localhost", str(port)])
            subprocess.run(["networksetup", "-setsecurewebproxy", "Wi-Fi", "localhost", str(port)])
        elif platform.system() == "Linux":
            # This varies by distro and desktop environment
            print(Fore.YELLOW + "Automatic proxy configuration not fully supported on Linux")
    except Exception as e:
        print(Fore.YELLOW + f"Failed to configure system proxy: {e}")

def restore_system_proxy():
    """Restore original proxy settings."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["netsh", "winhttp", "reset", "proxy"])
        elif platform.system() == "Darwin":
            subprocess.run(["networksetup", "-setwebproxystate", "Wi-Fi", "off"])
            subprocess.run(["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"])
    except Exception as e:
        print(Fore.YELLOW + f"Failed to restore proxy settings: {e}")

def parse_csv_to_list(csv_str: Optional[str], cast_type=str):
    if not csv_str:
        return None
    return [cast_type(x.strip()) for x in csv_str.split(",") if x.strip()]


import textwrap

INTERCEPTOR_TEMPLATE = textwrap.dedent('''
import re, time, json, os, base64, chardet, tempfile, ssl
from datetime import datetime, timedelta
from mitmproxy import http, certs
from OpenSSL import SSL
from colorama import Fore, Style
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from collections import deque
                                       

PORT = {0}
URL_CONTAINS = {1}
STATUS_CODES = {2}
METHODS = {3}
BLOCK_PATTERNS = {4}
EXCLUDE_DOMAINS = {5}
SENSITIVE_HEADERS = {6}
MAX_BODY_LENGTH = {7}
OUTPUT_FILE = {8}
OUTPUT_FORMAT = {9}  # "har", "json", "txt"
NO_SSL = {10}
RULES = {11}
INTERCEPTION_MODE = {12}  # "system", "single", "multiple"
TARGET_LIST = {13}
binary_threshold = {14}
IGNORE_EXTENSIONS = {15}  # e.g., [".jpg", ".png", ".css", ".js"]
                                       
# Console Colors
COLOR_REQUEST = Fore.CYAN
COLOR_RESPONSE = Fore.GREEN
COLOR_ERROR = Fore.RED
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.BLUE
RESET = Style.RESET_ALL
                                       

# Initialize with safe defaults
if not isinstance(RULES, list):
    try:
        RULES = json.loads(RULES) if RULES else []
    except json.JSONDecodeError:
        RULES = []


compiled_block = [re.compile(p) for p in (BLOCK_PATTERNS or [])]
# compiled_exclude = [re.compile(p) for p in (EXCLUDE_DOMAINS or [])]
                                       
MAX_DISPLAY_ENTRIES = 20
log_buffer = deque(maxlen=MAX_DISPLAY_ENTRIES)
                                       
collected_entries = []
all_entries = []
                                       
# Enhanced rule processing with error handling
processed_rules = []
for rule in RULES:
    try:
        if isinstance(rule, dict):
            processed_rules.append({{
                'compiled': re.compile(rule.get('pattern', '')),
                'action': rule.get('action', 'modify'),
                'replacement': rule.get('replacement'),
                'headers': rule.get('headers', {{}}),
                'status_code': rule.get('status_code')
            }})
        else:
            processed_rules.append({{'compiled': re.compile(rule), 'action': 'modify'}})
    except re.error as e:
        print(f"{{COLOR_ERROR}}[!] Invalid rule pattern: {{rule}} - {{e}}{{RESET}}")

def load_ignore_extensions(ignore):
    """Load IGNORE_EXTENSIONS from file, comma-separated string, or single value."""
    if not ignore:
        return []

    # If it's already a list, return lowercase copy
    if isinstance(ignore, list):
        return [item.strip().lower() for item in ignore if item.strip()]

    # If it's a file path
    if isinstance(ignore, str) and os.path.isfile(ignore):
        try:
            with open(ignore, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Failed to read ignore file: {{e}}")
            return []

    # Comma-separated string or single string
    return [item.strip().lower() for item in ignore.split(',') if item.strip()]

IGNORE_EXTENSIONS = load_ignore_extensions(IGNORE_EXTENSIONS)
                                                  
def should_ignore(flow: http.HTTPFlow) -> bool:
    """Skip flows based on URL extension"""
    url_path = flow.request.path.lower()
    for ext in (IGNORE_EXTENSIONS or []):
        if url_path.endswith(ext.lower()):
            return True
    return False

def print_banner():
    """Display a clear startup banner"""
    print(f"\\n{{COLOR_INFO}}╔{{'═'*60}}╗")
    print(f"║{{'HTTP INTERCEPTOR':^60}}║")
    print(f"╠{{'═'*60}}╣")
    print(f"║ {{COLOR_INFO}}Mode:{{RESET}} {{INTERCEPTION_MODE:<20}} {{COLOR_INFO}}Port:{{RESET}} {{PORT:<15}}          {{COLOR_INFO}} ║ {{RESET}}")
    print(f"║ {{COLOR_INFO}}Targets:{{RESET}} {{str(TARGET_LIST or 'All'):<49}} ║")
    print(f"║ {{COLOR_INFO}}Rules:{{RESET}}{{len(RULES):<52}} ║")
    print(f"╚{{'═'*60}}╝{{RESET}}\\n")

def print_http_event(flow, event_type):
    """Print formatted HTTP event to console"""
                                       
    if should_ignore(flow):
        return
                                       
    if event_type == "request":
        color = COLOR_REQUEST
        symbol = "↑"
        method = flow.request.method
        url = flow.request.pretty_url
    else:
        color = COLOR_RESPONSE
        symbol = "↓"
        method = flow.request.method  # Keep request method for correlation
        url = flow.request.pretty_url
        status = flow.response.status_code 
    
    # Basic info line
    if event_type == "request":
        base_line = f"{{symbol}} {{method}} {{url}}"
    else:
        base_line = f"{{symbol}} {{status}} {{method}} {{url}}"
    
    print(f"\\n{{color}}╔{{'═'*(len(base_line)+2)}}╗")
    print(f"║ {{base_line}} ║")
    print(f"╚{{'═'*(len(base_line)+2)}}╝{{RESET}}")
    
    # Additional details on demand
    if OUTPUT_FORMAT == "txt":
        if event_type == "request":
            print(f"{{color}}\\n=== REQUEST ===\\n{{RESET}}")
            print(f"{{color}}Headers:{{RESET}}")
            for k, v in flow.request.headers.items():
                print(f"  {{k}}: {{v}}")
            
            if flow.request.content:
                print(f"\\n{{color}}Body:{{RESET}}")
                print(process_content(flow.request.content))

            print("\\n" + f'{{color}}{{"="*80}}{{RESET}}' + "\\n\\n")
                                       
        else:
            print(f"{{color}}\\n=== RESPONSE ===\\n{{RESET}}")
            print(f"{{color}}Headers:{{RESET}}")
            for k, v in flow.response.headers.items():
                print(f"  {{k}}: {{v}}")
            
            if flow.response.content:
                print(f"\\n{{color}}Body:{{RESET}}")
                print(process_content(flow.response.content))
            print("\\n" + f'{{color}}{{"="*80}}{{RESET}}' + "\\n\\n")


def print_rule_action(flow, rule, action):
    colors = {{'block': COLOR_ERROR, 'redirect': COLOR_WARNING, 'modify': COLOR_INFO, 'respond': COLOR_WARNING}}
    print(f"{{colors.get(action, COLOR_INFO)}}[RULE] Applied {{action}} to {{flow.request.url}}{{RESET}}")

def print_status(message, status="info"):
    mapping = {{"info": (COLOR_INFO, "[*]"), "success": (COLOR_INFO, "[✓]"),
               "warning": (COLOR_WARNING, "[!]"), "error": (COLOR_ERROR, "[✗]")}}
    color, symbol = mapping.get(status.lower(), (COLOR_INFO, "[*]"))
    print(f"{{color}}{{symbol}} {{message}}{{RESET}}")


# --- Persistent CA paths ---
CA_KEY_FILE = "my_ca_key.pem"
CA_CERT_FILE = "my_ca_cert.pem"

def generate_or_load_ca():
    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        # Load existing CA
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    # Generate new CA
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyInterceptor"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyInterceptor CA"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))

    # Save for future runs
    with open(CA_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert

CA_KEY, CA_CERT = generate_or_load_ca()


# --- Ephemeral per-host certs stored in temp files ---
def generate_host_cert(hostname: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(CA_CERT.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=1))  # ephemeral 1 day
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(CA_KEY, hashes.SHA256()))

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Use temporary files that are deleted when closed
    cert_file = tempfile.NamedTemporaryFile(delete=True)
    key_file = tempfile.NamedTemporaryFile(delete=True)
    cert_file.write(cert_pem)
    key_file.write(key_pem)
    cert_file.flush()
    key_file.flush()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

    return ssl_context, cert_file, key_file

def load_exclude_list(ignore: str):
    ignore_list = []

    if ignore:
        # File mode
        if os.path.isfile(ignore):
            try:
                with open(ignore, 'r') as f:
                    lines = [line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")]
            except Exception as e:
                print(f"[!] Failed to read ignore file: {{e}}")
                raise SystemExit(1)
        # Comma-separated string mode
        else:
            lines = [item.strip().lower() for item in ignore.split(',') if item.strip()]

        # Convert lines to regex patterns
        for line in lines:
            if line.startswith("*."):
                # wildcard: *.example.com -> match any subdomain
                escaped = re.escape(line[2:])
                pattern = re.compile(rf".*\.{{escaped}}$")
            else:
                # exact match
                escaped = re.escape(line)
                pattern = re.compile(rf"^{{escaped}}$")
            ignore_list.append(pattern)

    return ignore_list

                         
compiled_exclude = load_exclude_list(EXCLUDE_DOMAINS)

                                       
def should_intercept(flow: http.HTTPFlow) -> bool:
    url_lower = flow.request.pretty_url.lower()
    host_lower = flow.request.host.lower()
    method_upper = flow.request.method.upper()
    target_set = {{t.lower() for t in TARGET_LIST}}

    if any(pat.match(host_lower) for pat in compiled_exclude):
        return False

    # Filter by interception mode and target list
    if INTERCEPTION_MODE != "system" and TARGET_LIST:
        if host_lower not in target_set:
            return False

    # Filter by URL contains
    if URL_CONTAINS and URL_CONTAINS.lower() not in url_lower:
        return False

    # Filter by HTTP methods
    if METHODS and method_upper not in (m.upper() for m in METHODS):
        return False

    # Filter by response status codes
    if STATUS_CODES:
        if not flow.response or flow.response.status_code not in STATUS_CODES:
            return False

    # Filter by exclude domains
    if EXCLUDE_DOMAINS:
        if any(pat.search(url_lower) for pat in compiled_exclude):
            return False

    return True



def process_content(content, max_length=MAX_BODY_LENGTH):
    """Robust content processing with binary detection and encoding auto-detection."""
    if not content:
        return ""
    
    try:
        # Handle bytes
        if isinstance(content, bytes):
            # Skip binary detection for very small payloads (<=4 bytes)
            if len(content) > 4:
                non_printables = sum(b < 9 or (13 < b < 32) or b > 126 for b in content)
                if (non_printables / len(content)) > binary_threshold:
                    return f"[BINARY: {{len(content)}} bytes]"
            
        # Fast path: try common encodings first
        for enc in ('utf-8', 'utf-16', 'utf-32', 'latin-1', 'ascii'):
            try:
                content = content.decode(enc)
                break
            except UnicodeDecodeError:
                    continue
        else:
            # Slow path: fall back to chardet
            detected = chardet.detect(content)
            encoding = detected.get('encoding') or 'utf-8'
            try:
                content = content.decode(encoding, errors='replace')
            except (LookupError, UnicodeDecodeError):
                return f"[BINARY: {{len(content)}} bytes]"

        # Ensure string and strip
        content = str(content).strip()

        # Try pretty-printing JSON if it looks like JSON
        if content.startswith(('{{', '[')):
            try:
                parsed = json.loads(content)
                return json.dumps(parsed, indent=2)[:max_length]
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        return content[:max_length]

    except Exception:
        return "[CONTENT PROCESSING ERROR]"


def redact_sensitive_data(headers):
    """Redact sensitive headers with case-insensitive matching"""
    return [
        (k, '[REDACTED]' if any(h.lower() == k.lower() for h in (SENSITIVE_HEADERS or [])) else v)
        for k, v in headers
    ]


def create_har_entry(flow, entry_type="response"):
    entry = {{
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request": {{
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": redact_sensitive_data(flow.request.headers.items()),
            "body": process_content(flow.request.content),
            "content_type": flow.request.headers.get("Content-Type", "")
        }}
    }}

    if entry_type == "response" and hasattr(flow, "response"):
        entry["response"] = {{
            "status": flow.response.status_code,
            "headers": redact_sensitive_data(flow.response.headers.items()),
            "body": process_content(flow.response.content),
            "content_type": flow.response.headers.get("Content-Type", ""),
            "statusText": flow.response.reason
        }}

    entry["type"] = entry_type
    return entry


def apply_rules(flow: http.HTTPFlow):
    for rule in processed_rules:
        try:
            if rule['compiled'].search(flow.request.pretty_url):
                action = rule.get('action', 'modify')
                if action == "block":
                    flow.response = http.HTTPResponse.make(
                        rule.get('status_code', 403),
                        b"Blocked by interceptor",
                        {{"Content-Type": "text/plain"}}
                    )
                elif action == "redirect":
                    flow.response = http.HTTPResponse.make(
                        rule.get('status_code', 302),
                        b"",
                        {{"Location": rule.get('replacement', "/")}}
                    )
                elif action == "respond":
                    flow.response = http.HTTPResponse.make(
                        rule.get('status_code', 200),
                        rule.get('replacement', "").encode() if rule.get('replacement') else b"",
                        {{"Content-Type": "text/plain"}}
                    )
                elif action == "modify":
                    if rule.get("headers"):
                        for k, v in rule["headers"].items():
                            flow.request.headers[k] = v
                    if rule.get("replacement") and flow.response:
                        flow.response.content = rule["replacement"].encode()
                print_rule_action(flow, rule, action)
        except Exception as e:
            print_status(f"Error applying rule {{rule.get('compiled')}}: {{e}}", "error")
                                       

def request(flow: http.HTTPFlow):

    if should_ignore(flow):
        return
                                       
    if not should_intercept(flow):
        return
        
    if not apply_rules(flow):
        print_status(f"Request blocked to {{flow.request.url}}", "warning")
        return
        
    custom_fn = globals().get("custom_request")
    if custom_fn:
        try:
            custom_fn(flow)
        except Exception as e:
            print(f"{{Fore.RED}}[!] Custom request error: {{e}}{{Style.RESET_ALL}}")
    
    print_http_event(flow, "request")
    # Create HAR entry with request only
    har_entry = create_har_entry(flow, "request")
    har_entry["_flow_obj"] = flow  
                                       
    collected_entries.append(har_entry)
    all_entries.append(har_entry)
    maintain_rolling_window()
                                       

def response(flow: http.HTTPFlow):
                                               
    if STATUS_CODES and flow.response.status_code not in STATUS_CODES:
        return

    if "custom_response" in globals():
        try:
            custom_response(flow)
        except Exception as e:
            print(f"{{Fore.RED}}[!] Custom response error: {{e}}{{Style.RESET_ALL}}")

    apply_rules(flow)
                                       
    # Find the existing request entry to update
    for entry in reversed(collected_entries):
        if entry.get("_flow_obj") == flow and "response" not in entry:
            entry.update(create_har_entry(flow, "response"))
            break
    else:
        # If not found, create a new entry (fallback)
        har_entry = create_har_entry(flow, "response")
        har_entry["_flow_obj"] = flow
        collected_entries.append(har_entry)
        all_entries.append(har_entry)
                                       
    print_http_event(flow, "response")
    maintain_rolling_window()
                                       
# Global counter
new_print_counter = 0

def maintain_rolling_window():
    """Maintain a rolling window of collected entries without clearing console"""
    global collected_entries, new_print_counter
                                       
    # Trim list if it exceeds MAX_DISPLAY_ENTRIES
    if len(collected_entries) > MAX_DISPLAY_ENTRIES or new_print_counter >= MAX_DISPLAY_ENTRIES:
        collected_entries[:] = collected_entries[-MAX_DISPLAY_ENTRIES:]
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()
        print_status(
            f"Displaying last {{len(collected_entries)}} entries of total {{len(all_entries)}}",
            "info"
        )

    # Print only the last entry (newest) to console
    last_entry = collected_entries[-1]
    printed = False
    if "request" in last_entry:
        print_http_event(last_entry["_flow_obj"], "request")
        printed = True
    if "response" in last_entry:
        print_http_event(last_entry["_flow_obj"], "response")
        printed = True

    if printed:
        new_print_counter += 1

    if new_print_counter > MAX_DISPLAY_ENTRIES:
        new_print_counter = 0


def save_output(entries, filename, format_type):
    """Handle all output formats with proper error handling"""
    try:
        if format_type == "har":
            har = {{
                "log": {{
                    "version": "1.2",
                    "creator":{{"name": "HTTP Interceptor", "version": "2.1"}},
                    "entries": [{{
                        "startedDateTime": e["timestamp"],
                        "request": {{
                            "method": e["request"]["method"],
                            "url": e["request"]["url"],
                            "headers": [{{"name": k, "value": v}} for k, v in e["request"]["headers"]],
                            "postData": {{
                                "mimeType": e["request"]["content_type"],
                                "text": e["request"]["body"]
                            }}
                        }},
                        "response": {{
                            "status": e["response"]["status"],
                            "headers": [{{"name": k, "value": v}} for k, v in e["response"]["headers"]],
                            "content": {{
                                "mimeType": e["response"]["content_type"],
                                "text": e["response"]["body"]
                            }}
                        }}
                    }} for e in entries]
                }}
            }}
            with open(filename, "w") as f:
                json.dump(har, f, indent=2)
        elif format_type == "json":
            with open(filename, "w") as f:
                json.dump(entries, f, indent=2)
        else:
            with open(filename, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(f"=== REQUEST ===\\n")
                    f.write(f"{{e['request']['method']}} {{e['request']['url']}}\\n")
                    f.write("Headers:\\n")
                    for k, v in e['request']['headers']:
                        f.write(f"  {{k}}: {{v}}\\n")
                    if e['request']['body']:
                        f.write(f"Body:\\n{{e['request']['body']}}\\n")
                    f.write(f"\\n=== RESPONSE ===\\n")
                    f.write(f"Status: {{e['response']['status']}} {{e['response'].get('statusText', '')}}\\n")
                    f.write("Headers:\\n")
                    for k, v in e['response']['headers']:
                        f.write(f"  {{k}}: {{v}}\\n")
                    if e['response']['body']:
                        f.write(f"Body:\\n{{e['response']['body']}}\\n")
                    f.write("\\n" + "="*80 + "\\n\\n")
    except Exception as e:
        print(f"{{Fore.RED}}[!] Failed to save output: {{e}}{{Style.RESET_ALL}}")

def done():
    if not collected_entries:
        print()
        print_status("No traffic captured\\n", "warning")
        return
    
    file_type = (
    "har" if OUTPUT_FILE.endswith(".har") else
    "json" if OUTPUT_FILE.endswith(".json") else
    "txt"
)

    if OUTPUT_FILE:
        try:
            save_output(all_entries, OUTPUT_FILE, file_type)
            print_status(f"Saved {{len(all_entries)}} entries to {{OUTPUT_FILE}}\\n", "success")
        except Exception as e:
            print_status(f"Failed to save output: {{str(e)}}\\n", "error")
                                       
print_banner()
''')