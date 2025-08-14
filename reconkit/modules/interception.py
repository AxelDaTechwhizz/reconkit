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
import re, json, os, base64
from datetime import datetime
from mitmproxy import http
from colorama import Fore, Style

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

                                       
# Console Colors
COLOR_REQUEST = Fore.CYAN
COLOR_RESPONSE = Fore.GREEN
COLOR_ERROR = Fore.RED
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.BLUE
RESET = Style.RESET_ALL
                                       

# Initialize with safe defaults
if not isinstance(RULES, list):
    RULES = json.loads(RULES) if RULES else []

compiled_block = [re.compile(p) for p in (BLOCK_PATTERNS or [])]
compiled_exclude = [re.compile(p) for p in (EXCLUDE_DOMAINS or [])]

def print_banner():
    """Display a clear startup banner"""
    print(f"\\n{{COLOR_INFO}}╔{{'═'*60}}╗")
    print(f"║{{'HTTP INTERCEPTOR':^60}}║")
    print(f"╠{{'═'*60}}╣")
    print(f"║ {{COLOR_INFO}}Mode:{{RESET}} {{INTERCEPTION_MODE:<20}} {{COLOR_INFO}}Port:{{RESET}} {{PORT:<15}}          {{COLOR_INFO}} ║ {{RESET}}")
    print(f"║ {{COLOR_INFO}}Targets:{{RESET}} {{str(TARGET_LIST or 'All'):<49}} ║")
    print(f"║ {{COLOR_INFO}}Rules:{{RESET}} {{len(RULES):<52}}║")
    print(f"╚{{'═'*60}}╝{{RESET}}\\n")

def print_http_event(flow, event_type):
    """Print formatted HTTP event to console"""
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
            print(f"{{color}}Request Headers:{{RESET}}")
            for k, v in flow.request.headers.items():
                print(f"  {{k}}: {{v}}")
            
            if flow.request.content:
                print(f"\\n{{color}}Request Body:{{RESET}}")
                print(process_content(flow.request.content))
        else:
            print(f"{{color}}Response Headers:{{RESET}}")
            for k, v in flow.response.headers.items():
                print(f"  {{k}}: {{v}}")
            
            if flow.response.content:
                print(f"\\n{{color}}Response Body:{{RESET}}")
                print(process_content(flow.response.content))

def print_rule_action(flow, rule, action):
    """Notify when rules are applied"""
    action_colors = {{
        'block': COLOR_ERROR,
        'redirect': COLOR_WARNING,
        'modify': COLOR_INFO,
        'respond': COLOR_WARNING
    }}
    print(f"{{action_colors.get(action, COLOR_INFO)}}"
          f"[RULE] Applied {{action}} to {{flow.request.url}}"
          f"{{RESET}}")

def print_status(message, status="info"):
    """Standardized status messages"""
    status_map = {{
        "info": (COLOR_INFO, "[*]"),
        "success": (COLOR_INFO, "[✓]"),
        "warning": (COLOR_WARNING, "[!]"),
        "error": (COLOR_ERROR, "[✗]")
    }}
    color, symbol = status_map.get(status.lower(), (COLOR_INFO, "[*]"))
    print(f"{{color}}{{symbol}} {{message}}{{RESET}}")

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
            processed_rules.append({{
                'compiled': re.compile(rule),
                'action': 'modify'
            }})
    except re.error as e:
        print(f"{{Fore.RED}}[!] Invalid rule pattern: {{rule}} - {{e}}{{Style.RESET_ALL}}")

collected_entries = []

def should_intercept(flow: http.HTTPFlow) -> bool:
    """Determine if we should process this flow with safe defaults"""
    if INTERCEPTION_MODE != "system" and TARGET_LIST:
        if flow.request.host.lower() not in [t.lower() for t in TARGET_LIST]:
            return False

    url_contains = URL_CONTAINS or ""
    if url_contains and url_contains.lower() not in flow.request.pretty_url.lower():
        return False
        
    if METHODS and flow.request.method.upper() not in [m.upper() for m in METHODS]:
        return False
        
    for pattern in compiled_block:
        if pattern.search(flow.request.pretty_url):
            flow.kill()
            return False
            
    for pattern in compiled_exclude:
        if pattern.search(flow.request.pretty_url):
            return False
            
    return True

def process_content(content, max_length=MAX_BODY_LENGTH):
    """Robust content processing with binary detection"""
    if not content:
        return ""
    
    try:
        if isinstance(content, bytes):
            try:
                content = content.decode('utf-8')
            except UnicodeDecodeError:
                return f"[BINARY: {{len(content)}} bytes]"
        
        content = str(content).strip()
        if content.startswith(('{{', '[')):
            try:
                parsed = json.loads(content)
                return json.dumps(parsed, indent=2)[:max_length]
            except json.JSONDecodeError:
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


def create_har_entry(flow):
    """Create standardized HAR entry with all required fields"""
    return {{
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request": {{
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": redact_sensitive_data(flow.request.headers.items()),
            "body": process_content(flow.request.content),
            "content_type": flow.request.headers.get("Content-Type", "")
        }},
        "response": {{
            "status": flow.response.status_code,
            "headers": redact_sensitive_data(flow.response.headers.items()),
            "body": process_content(flow.response.content),
            "content_type": flow.response.headers.get("Content-Type", ""),
            "statusText": flow.response.reason
        }}
    }}

def apply_rules(flow, rule_type='request'):
    """Unified rule application for both requests and responses"""
    for rule in processed_rules:
        if not rule['compiled'].search(flow.request.pretty_url):
            continue

        if rule['action'] == 'block' and rule_type == 'request':
            flow.kill()
            return False

        if rule['action'] == 'redirect' and rule['replacement'] and rule_type == 'request':
            flow.request.url = rule['compiled'].sub(rule['replacement'], flow.request.url)

        if rule['action'] in ('modify', 'replace'):
            target = flow.request if rule_type == 'request' else flow.response
            if rule['headers']:
                target.headers.update(rule['headers'])
            if rule['replacement'] and target.content:
                try:
                    body = target.content.decode('utf-8')
                    target.content = rule['compiled'].sub(rule['replacement'], body).encode('utf-8')
                except (UnicodeDecodeError, re.error):
                    pass

        if rule['action'] == 'respond' and rule['status_code'] and rule_type == 'request':
            flow.response = http.Response.make(
                rule['status_code'],
                b"",
                {{"Content-Type": "text/plain"}}
            )
            return False

    return True

def request(flow: http.HTTPFlow):
    if not should_intercept(flow):
        return
    
    print_http_event(flow, "request")
    
    if not apply_rules(flow, 'request'):
        print_status(f"Request blocked to {{flow.request.url}}", "warning")
        return
        
    if "custom_request" in globals():
        try:
            custom_request(flow)
        except Exception as e:
            print(f"{{Fore.RED}}[!] Custom request error: {{e}}{{Style.RESET_ALL}}")

def response(flow: http.HTTPFlow):
    if STATUS_CODES and flow.response.status_code not in STATUS_CODES:
        return

    print_http_event(flow, "response")
    apply_rules(flow, 'response')

    if "custom_response" in globals():
        try:
            custom_response(flow)
        except Exception as e:
            print(f"{{Fore.RED}}[!] Custom response error: {{e}}{{Style.RESET_ALL}}")

    collected_entries.append(create_har_entry(flow))

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
        else:
            with open(filename, "w") as f:
                json.dump(entries, f, indent=2)
        print(f"{{Fore.GREEN}}[+] Saved {{len(entries)}} entries to {{filename}}{{Style.RESET_ALL}}")
    except Exception as e:
        print(f"{{Fore.RED}}[!] Failed to save output: {{e}}{{Style.RESET_ALL}}")

def done():
    if not collected_entries:
        print_status("No traffic captured", "warning")
        return

    if OUTPUT_FILE:
        try:
            save_output(collected_entries, OUTPUT_FILE, 
                      "har" if OUTPUT_FILE.endswith('.har') else 
                      "json" if OUTPUT_FILE.endswith('.json') else 
                      OUTPUT_FORMAT)
            print_status(f"Saved {{len(collected_entries)}} entries to {{OUTPUT_FILE}}", "success")
        except Exception as e:
            print_status(f"Failed to save output: {{str(e)}}", "error")
                                       
print_banner()
print_status(f"Interceptor ready on port {{PORT}}", "success")
print_status(f"  Set system proxy to: http://localhost:{{PORT}}", "info")
print_status(f"  Mode: {{INTERCEPTION_MODE}}", "info")
print_status(f"  Targets: {{TARGET_LIST or 'All'}}", "info")
print_status(f"  Rules: {{len(RULES)}} configured", "info")
''')