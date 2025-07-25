"""
Identifies the tech stack being used in the website/page
Detects technologies like:
- Web servers (e.g., Apache, Nginx)
- Programming languages (e.g., Python, PHP)
- Frameworks (e.g., Django, Flask)
- Databases (e.g., MySQL, PostgreSQL)
- Content management systems (e.g., WordPress, Joomla)
- JavaScript libraries (e.g., jQuery, React)
- Other technologies (e.g., Redis, Memcached)
- SSL/TLS configurations

"""

import reconkit.modules.utils
import re
from ssl import create_default_context
from bs4 import BeautifulSoup
from reconkit.modules.config import TECH_SIGNATURES
from datetime import datetime,timezone
from socket import create_connection
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any


def get_headers_cookies(url: str, timeout: int,headers : dict,
                        verify_ssl: bool, allow_redirects: bool = True ):

      
      """
      Fetches headers and cookies from the given URL.
      """
      
      try:
            response = reconkit.modules.utils.fetch_with_retry(url,timeout=timeout,headers=headers,allow_redirects=allow_redirects,
                                              verify_ssl=verify_ssl)

            if not response or not response.ok:
                  reconkit.modules.utils.print_error(f"Bad response from {url}: {response.status_code if response else 'No Response'}")
                  return None, None

            # Extract headers and cookies
            headers = response.headers
            cookies = response.cookies.get_dict()
            if not headers:
                  reconkit.modules.utils.print_info(f"No headers found in {url}.")
            if not cookies:
                  reconkit.modules.utils.print_info(f"No cookies found in {url}.")
            if not headers and not cookies:
                  reconkit.modules.utils.print_info(f"No headers and cookies found in {url}.")
            return headers, cookies,response.text
      except Exception as e:
            reconkit.modules.utils.print_error(f"Error fetching headers and cookies: {e}")
            return None, None,None


def get_ssl_info(url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """
    Fetches SSL certificate information from the given URL.
    Returns details such as subject, issuer, validity dates, SANs, serial number, and TLS version.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            raise ValueError("Invalid URL: missing hostname")

        ssl_context = create_default_context()
        with create_connection((hostname, 443), timeout=timeout) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                days_remaining = None
                if not_after:
                    try:
                        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_remaining = (expiry_date - datetime.now(timezone.utc)).days
                    except Exception as date_err:
                        reconkit.modules.utils.print_error(f"Could not parse certificate expiry date: {date_err}")

                return {
                    "subject": ", ".join(f"{k}={v}" for tup in cert.get("subject", []) for k, v in tup),
                    "issuer": ", ".join(f"{k}={v}" for tup in cert.get("issuer", []) for k, v in tup),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": not_after,
                    "days_until_expiry": days_remaining,
                    "serial_number": str(cert.get("serialNumber", "N/A")),
                    "tls_version": ssock.version(),
                    "subject_alt_names": [val for typ, val in cert.get("subjectAltName",
                                                                        []) if typ == "DNS"]
                }

    except Exception as e:
        reconkit.modules.utils.print_error(f"Error getting SSL cert for {url}: {e}")
        return None

import sys
from tqdm import tqdm

def get_tech_stack(
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    content: str = ""
) -> Dict[str, List[str]]:

    if headers is None and cookies is None and not content:
        return {}

    detected: Dict[str, List[str]] = {}

    soup = BeautifulSoup(content, "html.parser") if content else None

    def match_headers(patterns: List[str]) -> bool:
        if not headers:
            return False
        for key, value in headers.items():
            line = f"{key}: {value}"
            if any(re.search(p, line) for p in patterns):
                return True
        return False

    def match_cookies(patterns: List[str]) -> bool:
        if not cookies:
            return False
        for name, value in cookies.items():
            combined = f"{name}={value}"
            if any(re.search(p, combined) for p in patterns):
                return True
        return False

    def match_content(patterns: List[str]) -> bool:
        if not content:
            return False
        return any(re.search(p, content) for p in patterns)

    def match_html(rules: List[Dict]) -> bool:
        if not soup:
            return False
        for rule in rules:
            if "tag" in rule:
                tag = rule["tag"]
                attrs = rule.get("attrs", {})
                def match_attrs(tag_obj):
                    for attr_key, attr_val in attrs.items():
                        if attr_key.endswith("_re"):
                            key = attr_key[:-3]
                            if not tag_obj.has_attr(key):
                                return False
                            if not re.search(attr_val, tag_obj[key], re.I):
                                return False
                        else:
                            if tag_obj.get(attr_key) != attr_val:
                                return False
                    return True
                if soup.find(tag, match_attrs):
                    return True
            elif "selector" in rule:
                if soup.select_one(rule["selector"]):
                    return True
        return False

    # Wrap signature loop with tqdm + guard
    tech_items = tqdm(TECH_SIGNATURES.items(), desc="Detecting technologies") \
                 if sys.stdout.isatty() else TECH_SIGNATURES.items()

    for tech, sig in tech_items:
        if (
            ('headers' in sig and match_headers(sig['headers']))
            or ('cookies' in sig and match_cookies(sig['cookies']))
            or ('content' in sig and match_content(sig['content']))
            or ('html' in sig and match_html(sig['html']))
        ):
            category = sig['category']
            detected.setdefault(category, []).append(tech)

    for category in detected:
        detected[category] = list(set(detected[category]))

    return detected
