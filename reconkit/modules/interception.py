import json,requests,platform,subprocess
from urllib.parse import urlparse
from requests.models import PreparedRequest, Response
from typing import Optional, List, Dict, Union
from colorama import init, Fore

init(autoreset=True)

class HttpInterceptor:
    def __init__(
        self,
        url_contains: Optional[str] = None,
        status_codes: Optional[List[int]] = None,
        max_body_length: int = 500,
        sensitive_headers: List[str] = ["Authorization", "Cookie"],
        log_file: Optional[str] = None,
        methods: Optional[List[str]] = None
    ):
        """Initialize the HTTP interceptor with configurable filters and options.
        
        Args:
            url_contains: Substring to match in URLs
            status_codes: List of status codes to log
            max_body_length: Maximum characters to log from body content
            sensitive_headers: Headers to redact from logs
            log_file: Path to file for logging (None for stdout)
            methods: HTTP methods to log (None for all)
        """
        self.filters = {
            "url_contains": url_contains,
            "status_codes": status_codes,
            "methods": methods
        }
        self.max_body_length = max_body_length
        self.sensitive_headers = sensitive_headers
        self.log_file = log_file

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

    def _should_log(self, req: PreparedRequest, resp: Optional[Response] = None) -> bool:
        """Determine if the request/response should be logged based on filters."""
        # Check URL filter
        if self.filters["url_contains"] and self.filters["url_contains"] not in req.url:
            return False
            
        # Check method filter
        if self.filters["methods"] and req.method not in self.filters["methods"]:
            return False
            
        # Check status code filter (only applicable if response exists)
        if resp and self.filters["status_codes"] and resp.status_code not in self.filters["status_codes"]:
            return False
            
        return True

    def _redact_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive headers from the log output."""
        return {
            k: "[REDACTED]" if k in self.sensitive_headers else v
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


def configure_system_proxy():
    """Attempt to configure system proxy settings automatically."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["netsh", "winhttp", "set", "proxy", "localhost:8080"])
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["networksetup", "-setwebproxy", "Wi-Fi", "localhost", "8080"])
            subprocess.run(["networksetup", "-setsecurewebproxy", "Wi-Fi", "localhost", "8080"])
        elif platform.system() == "Linux":
            # This varies by distro and desktop environment
            print(Fore.YELLOW + f"[/('_')\\] Automatic proxy configuration not fully supported on Linux")
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

INTERCEPTOR_TEMPLATE = """
import re,json
from mitmproxy import http
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from colorama import init, Fore

init(autoreset=True)

class ProxyInterceptor:
    def __init__(
        self,
        port: int = {port},
        url_contains: str = {url_contains},
        status_codes: list[int] = {status_codes},
        max_body_length: int = {max_body_length},
        sensitive_headers: list[str] = {sensitive_headers},
        log_file: str = {log_file},
        methods: list[str] = {methods},
        block_patterns: list[str] = {block_patterns},
        output_format: str = {output_format},
        exclude_domains: list[str] = {exclude_domains},
        no_ssl: bool = {no_ssl}
    ):
        self.port = port
        self.url_contains = url_contains
        self.status_codes = status_codes
        self.max_body_length = max_body_length
        self.sensitive_headers = [h.lower() for h in (sensitive_headers or ["authorization", "cookie"])]
        self.log_file = log_file
        self.methods = [m.upper() for m in (methods or [])]
        self.block_patterns = [re.compile(p) for p in (block_patterns or [])]
        self.output_format = output_format
        self.exclude_domains = exclude_domains or []
        self.no_ssl = no_ssl
        
        if output_format == "har" and log_file:
            self._init_har_file()

    def _should_exclude(self, url: str) -> bool:
        if not self.exclude_domains:
            return False
        return any(exclude_domain.lower() in url.lower() for exclude_domain in self.exclude_domains)

    def _init_har_file(self):
        '''Initialize HAR file with template if it doesn't exist'''
        if not Path(self.log_file).exists():
            har_template = {{
                "log": {{
                    "version": "1.2",
                    "creator": {{"name": "mitmproxy-interceptor", "version": "1.0"}},
                    "entries": []
                }}
            }}
            Path(self.log_file).write_text(json.dumps(har_template))

    def _should_block(self, url: str) -> bool:
        '''Check if URL matches any block patterns'''
        return any(pattern.search(url) for pattern in self.block_patterns)

    def _should_log(self, flow: http.HTTPFlow, is_response=False) -> bool:
        '''Enhanced filter checking with regex support'''
        if self._should_block(flow.request.pretty_url):
            return False
            
        if self.url_contains:
            try:
                if not re.search(self.url_contains, flow.request.pretty_url):
                    return False
            except re.error:
                if self.url_contains not in flow.request.pretty_url:
                    return False
                    
        if self.methods and flow.request.method.upper() not in self.methods:
            return False
            
        if is_response and self.status_codes and flow.response.status_code not in self.status_codes:
            return False
            
        return True

    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        '''Redact sensitive headers case-insensitively'''
        return {{
            k: ("[REDACTED]" if k.lower() in self.sensitive_headers else v)
            for k, v in headers.items()
        }}

    def _format_content(self, content: bytes) -> Tuple[str, Optional[dict]]:
        '''Format content based on output format'''
        if not content:
            return "", None
            
        try:
            text = content.decode("utf-8")
            parsed = json.loads(text)
            if self.output_format == "text":
                pretty = json.dumps(parsed, indent=2)
                return pretty[:self.max_body_length], parsed
            return text[:self.max_body_length], parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                text = content.decode("utf-8", errors="replace")
                return text[:self.max_body_length], None
            except Exception:
                return "[binary data]", None

    def _write_har_entry(self, flow: http.HTTPFlow):
        '''Write entry in HAR format'''
        if not self.log_file:
            return
            
        try:
            har_data = json.loads(Path(self.log_file).read_text())
            entry = {{
                "startedDateTime": datetime.utcnow().isoformat() + "Z",
                "request": {{
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "headers": [{{"name": k, "value": v}} for k, v in self._redact_headers(flow.request.headers).items()],
                    "postData": {{
                        "text": self._format_content(flow.request.content)[0]
                    }} if flow.request.content else None
                }},
                "response": {{
                    "status": flow.response.status_code,
                    "headers": [{{"name": k, "value": v}} for k, v in self._redact_headers(flow.response.headers).items()],
                    "content": {{
                        "text": self._format_content(flow.response.content)[0]
                    }} if flow.response.content else None
                }},
                "time": (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
            }}
            har_data["log"]["entries"].append(entry)
            Path(self.log_file).write_text(json.dumps(har_data, indent=2))
        except Exception as e:
            print(f"[ERROR] Failed to write HAR entry: {{e}}")

    def _write_log_entry(self, flow: http.HTTPFlow, is_response: bool):
        '''Write log entry in text or JSON format'''
        if self.output_format == "json":
            entry = {{
                "timestamp": datetime.utcnow().isoformat(),
                "type": "response" if is_response else "request",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status": flow.response.status_code if is_response else None,
                "headers": self._redact_headers(flow.response.headers if is_response else flow.request.headers),
                "body": self._format_content(flow.response.content if is_response else flow.request.content)[0]
            }}
            output = json.dumps(entry)
        else:  # text format
            divider = "=" * 60
            lines = [divider]
            if is_response:
                lines.append(f"[HTTP RESPONSE] {{flow.request.method}} {{flow.request.pretty_url}}")
                lines.append(f"Status: {{flow.response.status_code}}")
                for k, v in self._redact_headers(flow.response.headers).items():
                    lines.append(f"  < {{k}}: {{v}}")
                if flow.response.content:
                    content, _ = self._format_content(flow.response.content)
                    lines.append(f"  < Body:\\n{{content}}")
            else:
                lines.append(f"[HTTP REQUEST] {{flow.request.method}} {{flow.request.pretty_url}}")
                for k, v in self._redact_headers(flow.request.headers).items():
                    lines.append(f"  > {{k}}: {{v}}")
                if flow.request.content:
                    content, _ = self._format_content(flow.request.content)
                    lines.append(f"  > Body:\\n{{content}}")
            lines.append(divider)
            output = "\\n".join(lines)

        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(output + "\\n")
        else:
            print(output)

    def request(self, flow: http.HTTPFlow):
    
        if self._should_exclude(flow.request.pretty_url):
            return

        if self.no_ssl and flow.request.scheme == "https":
            return

        if self._should_block(flow.request.pretty_url):
            flow.kill()
            return
            
        if not self._should_log(flow):
            return
            
        if self.output_format == "har":
            # HAR entries are written only after response
            return
            
        self._write_log_entry(flow, is_response=False)

    def response(self, flow: http.HTTPFlow):
    
        if self._should_exclude(flow.request.pretty_url):
            return

        if self.no_ssl and flow.request.scheme == "https":
            return

        if not self._should_log(flow, is_response=True):
            return
            
        if self.output_format == "har":
            self._write_har_entry(flow)
        else:
            self._write_log_entry(flow, is_response=True)


addons = [
    ProxyInterceptor(
        port={port},
        url_contains={url_contains},
        status_codes={status_codes},
        max_body_length={max_body_length},
        sensitive_headers={sensitive_headers},
        log_file={log_file},
        methods={methods},
        block_patterns={block_patterns},
        output_format={output_format},
        exclude_domains={exclude_domains},
        no_ssl={no_ssl}
    )
]

# Add port binding info (for clarity)
print(Fore.GREEN + f'''ProxyInterceptor running on port {{addons[0].port}} with filters:
        Excluding       : {{addons[0].exclude_domains}},
        URL contains    : {{addons[0].url_contains}},
        Status codes    : {{addons[0].status_codes}},
        Methods         : {{addons[0].methods}},
        Max body length : {{addons[0].max_body_length}} characters,
        Headers redacted: {{addons[0].sensitive_headers}}
        ''')
"""
