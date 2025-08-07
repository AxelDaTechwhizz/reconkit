"""
Helper functions for the tool
"""
import os
import json
import csv
import string
import requests
import re
import traceback
from random import uniform
from time import sleep
from typing import Any,Optional
from urllib.parse import urlparse
from colorama import Fore,init,Style

"""
colorama initialization
This will allow us to use colored output in the terminal
"""
# initialize Colorama
init(autoreset=True)

"""
Functions to print messages in different colors
These functions will be used to print messages in the terminal
"""
def print_info(message, log : bool = False):
    if log:
        log_to_file(message, 'debug')
    print(Fore.CYAN + f"[(-_-)...] {message}")
    

def print_success(message, log : bool = False):
    if log:
        log_to_file(message, 'info')
    print(Fore.GREEN + f"[/(^_^)/] {message}")
    

def print_warning(message, log : bool = True,show_traceback : bool = False):
    if log:    
        log_to_file(message, 'warning')
    print(Fore.YELLOW + f"[/('_')\\] {message}")
    if show_traceback:
        print(Fore.RED + traceback.format_exc())


def print_error(message, log : bool = True,show_traceback : bool = False):
    if log:
        log_to_file(message, 'error')
    print(Fore.RED + f"[/(>_<)\\] {message}")
    if show_traceback:
        print(Fore.RED + traceback.format_exc())


"""
Functions to fetch URLs and handle errors
"""

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def fetch_url(url: str, headers: Optional[dict], timeout: int,
              verify_ssl: bool, allow_redirects: bool = True):
    """
    Fetches the given URL with optional headers and SSL verification.

    :param url: The full URL to request (http/https)
    :param headers: Optional headers dict
    :param timeout: Timeout in seconds
    :param verify_ssl: Whether to verify SSL certificates
    """
    try:
        response = requests.get(url, headers=headers, timeout=timeout,
                                allow_redirects=allow_redirects, verify=verify_ssl)
        return response
    except requests.exceptions.Timeout:
        print_warning(f'[!⏰] Request timed out: {url}')
        raise
    except requests.ConnectionError:
        print_warning(f"[/('_')\\] Connection error: {url}")
        raise
    except requests.RequestException as e:
        print_warning(f"[x_x] Request failed: {url} | {e}")
        raise



from time import sleep
from random import uniform

def fetch_with_retry(url: str, headers: dict, timeout: int, verify_ssl: bool,
                     allow_redirects: bool, throttle: float, retries: int = 3):
    """Fetch a URL with retry and exponential backoff. Returns response or None."""
    throttle = AdaptiveThrottle(throttle)
    default_wait_time = 10

    for attempt in range(retries):
        try:
            throttle.wait()
            response = fetch_url(url, headers=headers, timeout=timeout,
                                 allow_redirects=allow_redirects, verify_ssl=verify_ssl)

            if response.status_code in [429, 503]:
                retry_after = response.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else default_wait_time
                throttle.failure()
            else:
                throttle.success()
                return response

        except Exception as e:
            print_error(f"Fetch failed: {e}")
            wait_time = default_wait_time

        sleep(wait_time ** attempt + uniform(0, 1))

    return None  # ✅ Don't raise — let caller handle it



"""
Function to validate a URL
"""

def validate_url(url: str) -> str | None:
    """
    Validates and normalizes a URL. Adds scheme if missing.
    Returns the valid URL or None if invalid.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL format: {url}")
    return url
    
 
import time

class AdaptiveThrottle:
    def __init__(self, base_wait: float):
        if base_wait < 0:
            raise ValueError("Wait time cannot be negative.")
        self.base_wait = base_wait
        self.multiplier = 1.0
        self.max_multiplier = 16.0  # max backoff multiplier
        self.failures = 0
    
    def wait(self):
        adaptive_wait = self.base_wait * self.multiplier
        time.sleep(adaptive_wait)
    
    def success(self):
        """Call this when a request succeeds to reset multiplier."""
        self.failures = 0
        self.multiplier = 1.0
    
    def failure(self):
        """Call this when a request fails to increase wait time."""
        self.failures += 1
        self.multiplier = min(self.max_multiplier, self.multiplier * 2)
        print_info(f"[Throttle] Failure #{self.failures} detected, increasing wait multiplier to {self.multiplier}.")

def random_throttle(min_delay : float, max_delay:float):
    """
    Randomization to avoid pattern detection
    """
    if min_delay < 0 or max_delay < 0:
        print_error('Delay values cannot be negative.')
        return
    if min_delay > max_delay:
        print_error('Minimum delay cannot be greater than maximum delay.')
        return
    delay = round(uniform(min_delay,max_delay),2)
    sleep(delay)

"""
Function to validate input file
"""

def validate_input_file(filename: str) -> str:
    """
    Validates a file path. If it's an absolute path and exists, returns it.
    Otherwise, searches upward from the current directory, recursively through subdirectories,
    until the file is found.

    :param filename: Path or name of the file
    :return: Absolute path to the located file
    :raises FileNotFoundError: If the file is not found
    """

    # Absolute path provided
    if os.path.isabs(filename):
        if os.path.isfile(filename):
            return os.path.abspath(filename)
        else:
            raise FileNotFoundError(f"File not found: {filename}")

    # Relative name – search upward recursively
    visited = set()
    current_dir = os.getcwd()

    while True:
        if current_dir in visited:
            break
        visited.add(current_dir)

        for root, _, files in os.walk(current_dir):
            if filename in files:
                return os.path.abspath(os.path.join(root, filename))

        parent = os.path.dirname(current_dir)
        if parent == current_dir:
            break
        current_dir = parent

    raise FileNotFoundError(f"File not found: {filename}")

   

"""
Function to save data to a file
"""
def save_to_file(filename: str, data: Any):
    """
    Saves data to a file in .json, .csv, or .txt format based on extension.
    Smart formatting for different data types.
    """

    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    valid_formats = {'json', 'csv', 'txt'}

    if not ext:
        filename += ".txt"
        ext = 'txt'

    if ext not in valid_formats:
        print_error(f"Unsupported file extension: .{ext}")
        return

    # Normalize path
    filename = filename.lstrip("/\\")
    if filename.startswith("Results/") or filename.startswith("Results\\"):
        filename = filename.split(os.sep, 1)[-1]

    os.makedirs("Results", exist_ok=True)
    filename = os.path.join("Results", filename)

    # Pre-process sets for JSON
    if isinstance(data, set):
        data = list(data)

    try:
        with open(filename, 'w', encoding='utf-8', newline='') as file:
            if ext == 'json':
                if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                    for item in data:
                        file.write(json.dumps(item, indent=2) + '\n')
                else:
                    json.dump(data, file, indent=2)

            elif ext == 'csv':
                writer = csv.writer(file)
                if isinstance(data, list):
                    if all(isinstance(row, (list, tuple)) for row in data):
                        writer.writerows(data)
                    else:
                        for item in data:
                            writer.writerow([item])
                elif isinstance(data, dict):
                    for k, v in data.items():
                        writer.writerow([k, v])
                else:
                    writer.writerow([str(data)])

            elif ext == 'txt':
                if isinstance(data, (list, set, tuple)):
                    for item in data:
                        file.write(f"{item}\n")
                elif isinstance(data, dict):
                    for k, v in data.items():
                        file.write(f"{k}: {v}\n")
                else:
                    file.write(str(data))

        print_success(f"Data saved to: {filename}")

    except Exception as e:
        print_error(f"Failed to save file: {e}")

"""
Function to extract domains from text or file
"""


def extract_domains_from_text(data: str) -> list[str]:
    """
    Extracts domain names from a block of text by identifying URLs and parsing hostnames.

    :param data: Raw text input
    :return: Sorted list of unique domains found
    """
    # Regex to find all potential URLs
    url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    urls = url_pattern.findall(data)

    domains = set()

    for url in urls:
        # Clean trailing punctuation from URLs (e.g., "example.com.")
        cleaned_url = url.strip(string.punctuation)

        try:
            parsed = urlparse(cleaned_url)
            hostname = parsed.netloc.lower().strip()

            # Remove port if present (e.g., example.com:8080 -> example.com)
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            if hostname:
                domains.add(hostname)
        except Exception:
            continue  # Ignore malformed URLs

    return sorted(domains)


"""
This function reads a file and extracts domains from URLs found in the text.
"""

def extract_domains_from_file(filename):

    """
    Extracts domains from a file containing text data
    """
    # Extract from file

    try:
        with open(filename,'r',encoding='utf-8',errors='ignore') as file:

            url_pattern = re.compile(r'https?://[^\s\'"<>]+',re.IGNORECASE)
            urls = set()
            for line in file:
                line = line
                urls.update(re.findall(url_pattern, line))
            
            domains = set()
            for url in urls:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc.lower())
    
    except FileNotFoundError:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {filename}')
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error reading file: {e}')

    return sorted(domains)
            
"""
Logging function to append messages to a log file
"""
import logging


def setup_logger(log_filename='tool.log'):
    logger = logging.getLogger('reconkit')
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers
    if not logger.handlers:
        log_file_path = os.path.join(os.getcwd(), log_filename)
        handler = logging.FileHandler(log_file_path)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

# Use this throughout your app
logger = setup_logger()

def log_to_file(message: str, level: str = 'info'):
    level = level.lower()
    if level == 'debug':
        logger.debug(message)
    elif level == 'warning':
        logger.warning(message)
    elif level == 'error':
        logger.error(message)
    else:
        logger.info(message)


"""
validate_domain function to check if a string is a valid domain name
"""

import ipaddress


def is_valid_domain(domain: str) -> bool:
    """
    Validates if the input is a proper domain name (not an IP address),
    and explicitly allows 'localhost' for local testing.
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    # Explicitly allow localhost
    if domain == "localhost":
        return True

    # Optionally allow local loopback IPs (remove if you want only 'localhost')
    if domain in ["127.0.0.1", "::1"]:
        return True

    # Reject if it's an IP address
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    try:
        domain_ascii = domain.encode('idna').decode('ascii')
    except Exception:
        return False

    if len(domain_ascii) > 253:
        return False

    labels = domain_ascii.split('.')
    domain_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

    return all(domain_regex.match(label) for label in labels)


def list_files_in_folder(folder_path, ext=".json"):
    try:
        with os.scandir(folder_path) as entries:
            files = [entry.path for entry in entries if entry.is_file() and entry.name.endswith(ext)]
        return files
    except Exception as e:
        print_error(f"Error reading folder: {e}")
        return []
