"""
RECONKIT TOOL WITH:
    - HTTP DIRBRUTE
    - SUBDOMAIN ENUMERATION
    - TECH FINGERPRINTING
    - CVE SCANNER
    - HTTP Interceptor
    - Metric Scanner
"""

import re, typer, time, requests, json, os, platform, threading, gzip, shutil, tempfile, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from deepdiff import DeepDiff
from functools import lru_cache, wraps
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Optional, List, Dict, Callable
from tempfile import NamedTemporaryFile
from dataclasses import dataclass

# Import all module components
from reconkit.modules.cvescanner import scan_for_cves_local, init_cve_db, import_cves_from_json
from reconkit.modules.dirbrute import http_dir_bruteforcer, extract_path_prefixes_from_html
from reconkit.modules.techfingerprint import get_headers_cookies, get_tech_stack, get_ssl_info
from reconkit.modules.config import load_user_config, save_user_config, DEFAULT_CONFIG_PATH
from reconkit.modules.utils import (
    validate_url, print_error, print_success, print_warning, print_info,
    is_valid_domain, validate_input_file, save_to_file, list_files_in_folder,
    fetch_with_retry, log_to_file
)
from reconkit.modules.subdomain import (
    subdomain_finder,
    subdomain_from_file,
    generate_custom_wordlist
)
from reconkit.modules.interception import (
    INTERCEPTOR_TEMPLATE, parse_csv_to_list,
    configure_system_proxy, restore_system_proxy
)
from reconkit.modules.metricprobe import scan_target, batch_metric_probe


@dataclass
class TrafficRule:
    """Defines rules for traffic modification in the interceptor"""
    pattern: str          # Regex pattern to match
    action: str           # 'modify', 'block', 'redirect', 'mock'
    replacement: Optional[str] = None       # For modify/redirect actions
    headers: Optional[Dict[str, str]] = None # Headers to add/modify
    status_code: Optional[int] = None       # For mock responses
    mock_response: Optional[Dict] = None    # Complete mock response

app = typer.Typer(help="ReconKit: A modular recon tool for dir brute-force, subdomain enum, tech detection, and CVE scanning.")
app.pretty_exceptions_enabled = True

# Constants
CVE_DB_PATH = "cves.db"
__version__ = "2.2.0"  # Updated version

# Configuration
config = load_user_config()

SAFE_MODE_SETTINGS = {
    "max_wordlist_size": 500,   # Max number of lines to use from wordlist
    "max_domains": 10,          # Max domains to process in batch mode
    "no_recursive_subdomains": True,  # Disable recursive by default
    "limit_tech_stack": True    # Don't run SSL info or deep matching
}

# Helper Functions
def print_version_and_exit(value: bool):
    if value:
        print_success(f"ReconKit version {__version__}", log=config.get("log"))
        raise typer.Exit()

def safe_cli(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            print_error(f"Error: {e}", show_traceback=config.get("debug"))
            raise typer.Exit(code=1)
    return wrapper

def auto_tune_rate_limits(url: str):
    """Enhanced auto-tuning with jitter calculation"""
    try:
        delays = []
        headers = prepare_headers()

        # Validate and lock in current settings
        current_settings = {
            'delay': max(0.1, float(config.get("source_delay", 2.0))),
            'min': max(0.1, float(config.get("min_delay", 0.5))),
            'max': max(0.1, float(config.get("max_delay", 5.0))),
            'timeout': float(config.get("timeout", 10.0)),
            'verify_ssl': bool(config.get("verify_ssl", True))
        }

        for _ in range(5):
            start = time.time()
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=current_settings['timeout'],
                    verify=current_settings['verify_ssl']
                )
                elapsed = time.time() - start
                if response.status_code < 400:
                    delays.append(elapsed)
                # Apply throttle between requests
                time.sleep(current_settings['delay'])
            except Exception as e:
                print_warning(f"[auto-tune] Request failed: {e}")
                continue

        if delays:
            avg = sum(delays) / len(delays)
            jitter = max(delays) - min(delays)
            
            # Calculate new delay
            if avg > 2.0:
                new_delay = min(avg + (jitter * 0.5), current_settings['max'])
            elif avg > 1.0:
                new_delay = max(avg, current_settings['min'])
            else:
                new_delay = current_settings['min']
            
            # Update config safely
            config.update({
                'source_delay': float(new_delay),
                'min_delay': float(current_settings['min']),
                'max_delay': float(current_settings['max'])
            })
            
            print_info(
                f"[auto-tune] Set delay to {new_delay:.2f}s "
                f"(avg: {avg:.2f}s, jitter: {jitter:.2f}s)", 
                log=config['log']
            )
            return new_delay
        
        return current_settings['delay']
        
    except Exception as e:
        print_warning(f"[auto-tune] Failed: {str(e)}")
        return config.get("source_delay", 2.0)



def prepare_headers(input_headers: Optional[str] = None) -> dict:
    """Enhanced header preparation with security headers"""
    headers_dict = {
        "User-Agent": "ReconKit/2.2",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    
    if input_headers:
        for item in input_headers.split(';'):
            if ':' in item:
                key, value = item.strip().split(':', 1)
                headers_dict[key.strip()] = value.strip()


    # Profile-specific User-Agent tagging
    PROFILE_UA_TAGS = {
    "bugbounty-vidaxl": " -BugBounty-vidaxl-holding-31337",
    "yeswehack-dojo": " -BugBounty-yeswehack-dojo",
}

    profile = config.get("profile")
    ua_tag = PROFILE_UA_TAGS.get(profile)

    if ua_tag and ua_tag not in headers_dict["User-Agent"]:
        headers_dict["User-Agent"] += f" {ua_tag}"

    return headers_dict

def apply_profile(profile_name: str):
    if profile_name == "bugbounty-vidaxl":
        print_info("[*] Profile 'bugbounty-vidaxl' activated.", log=config["log"])
        config.update({
            'workers': 2,
            'source_delay': 3.0,
            'min_delay': 2.0,
            'max_delay': 6.0,
            'disable_dirbrute': True
        })

    elif profile_name == "yeswehack-dojo":
        print_info("[*] Profile 'yeswehack-dojo' activated.", log=config["log"])
        config.update({
            'workers': 1,
            'source_delay': 3.0,
            'min_delay': 1.0,
            'max_delay': 5.5,
            'disable_dirbrute': False,
            'respect_robots': True,
            'timeout': 15
        })


def show_warning_message(ctx : typer.Context, **kwargs):
    print_info("⚠️  Use only on targets you are authorized to scan. Unauthorized use is illegal.")
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

def ensure_data_dirs():
    os.makedirs("cves_jsons", exist_ok=True)
    if not os.path.exists("cves.db"):
        print_info("[*] Initializing empty CVE DB... Run `reconkit update-cves`.")
        init_cve_db("cves.db")

def show_support():
    print("❤️  Like ReconKit? Support future development:")
    print("☕  https://ko-fi.com/nyxsynn")

@app.callback(invoke_without_command=True)
@safe_cli
def callback(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(None, "--version", "-v", callback=print_version_and_exit),
    timeout: int = typer.Option(20, '-t', '--timeout'),
    workers: int = typer.Option(10, '-w', '--workers'),
    file_format: str = typer.Option('txt', '-f', '--format'),
    throttle: float = typer.Option(2.5, '-th', '--throttle'),
    throttle_min: float = typer.Option(2.0, '-tm', '--throttle-min'),
    throttle_max: float = typer.Option(6.0, '-tx', '--throttle-max'),
    verify_ssl: bool = typer.Option(True, '-s', '--verify-ssl'),
    debug: bool = typer.Option(False, '--debug'),
    log: bool = typer.Option(False, '--log'),
    profile: Optional[str] = typer.Option(None, '--profile', '-p'),
    save_conf: bool = typer.Option(False, "--save-config"),
    support: bool = typer.Option(False, '--support')
):
    """Enhanced main callback with new features"""
    if support:
        show_support()
    
    if ctx.invoked_subcommand is None:
        show_warning_message(ctx)
        raise typer.Exit()

    ensure_data_dirs()
    
    if support:
        show_support()
    
    show_warning_message(ctx)

    if profile:
        config.update({
            'profile': profile
        })
        apply_profile(profile_name=profile,log=log)
    
    if version:
        print_version_and_exit()

    cli_config = {
        "timeout": float(timeout) if timeout is not None else 10,
        "workers": int(workers) if workers is not None else 5,
        "file_format": file_format or "txt",
        "source_delay": max(0.1, float(throttle if throttle is not None else 2.5)),
        "min_delay": max(0.1, float(throttle_min if throttle_min is not None else 2.0)),
        "max_delay": max(0.1, float(throttle_max if throttle_max is not None else 6.0)),
        "verify_ssl": bool(verify_ssl),
        "debug": bool(debug),
        "log": log or None,
        "profile": profile or None
    }

    config.update(cli_config)

    if not os.path.exists(DEFAULT_CONFIG_PATH):
        save_user_config(config)
        print_success(f"Settings saved to {DEFAULT_CONFIG_PATH}", log=config.get("log")) 
    elif save_conf:
        existing_config = load_user_config()
        diff = DeepDiff(existing_config, config, ignore_order=True)
        if diff:
            save_user_config(config)
            print_success(f"[+] Updated config saved to {DEFAULT_CONFIG_PATH}", log=config.get("log"))
        else:
            print_info("[=] No config changes to save.", log=config.get("log"))

def get_robots_disallowed_paths(base_url: str) -> set:
    disallowed_paths = set()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = requests.get(robots_url, timeout=5)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed_paths.add(path)
    except Exception as e:
        # Fail silently if robots.txt cannot be fetched or parsed
        pass
    return disallowed_paths

    
@app.command(
    "intercept",
    help="Run proxy-based system-wide HTTP interceptor with advanced filters."
)
def intercept(
    targets: Optional[str] = typer.Option(None, "--targets", help="Comma-separated target hosts or URLs. Leave empty for system-wide."),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Single or Comma-separated list of domains to exclude from interception (e.g., example.com,api.example.com), \n" \
    "Can also be file path with one domain per line."),
    ignore: Optional[str] = typer.Option(None, "--ignore", help="Extensions to ignore (e.g., .jpg,.png,.css,.js)"),
    port: int = typer.Option(8080, "--port"),
    url_contains: Optional[str] = typer.Option(None, "--url-contains"),
    no_ssl: bool = typer.Option(False, "--no-ssl"),
    status_codes: Optional[str] = typer.Option(None, "--status-codes"),
    methods: Optional[str] = typer.Option(None, "--methods"),
    max_body_length: int = typer.Option(500, "--max-body"),
    sensitive_headers: str = typer.Option("authorization,cookie", "--redact-headers"),
    log_file: Optional[str] = typer.Option(None, "--log-file"),
    output_format: str = typer.Option("txt", "--format"),
    block_patterns: Optional[str] = typer.Option(None, "--block"),
    auto_proxy: bool = typer.Option(False, "--auto-proxy"),
    ssl_cert: Optional[str] = typer.Option(None, "--ssl-cert"),
    quiet: bool = typer.Option(False, "--quiet"),
    binary_threshold: float = typer.Option(0.8, "--binary-threshold", help="Threshold for binary content detection (0.0 - 1.0)(0.1 = 10%)"),
    rules_file: Optional[str] = typer.Option(None, "--rules-file", help="JSON file containing traffic rules"),
    test_rules: bool = typer.Option(False, "--test-rules", help="Validate rules file without running interceptor"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be intercepted without running"),
    preview_rules: bool = typer.Option(False, "--preview-rules", help="Display loaded rules before starting")
):
    """Run proxy-based system-wide HTTP interceptor with advanced filters."""

    # ---------- Validation ---------

    if not (0.0 <= binary_threshold <= 1.0):
        print_error("Binary threshold must be between 0.0 and 1.0")
        raise typer.Exit(code=1)
     
    valid_formats = ["har", "json", "txt"]
    output_format = output_format.lower()
    if output_format not in valid_formats:
        print_error(f"Invalid output format. Must be one of: {', '.join(valid_formats)}")
        raise typer.Exit(code=1)

    # ---------- Helper functions ----------
    def parse_status_codes(codes: str) -> list[int]:
        try:
            parsed = [int(c) for c in codes.split(',')]
            if not all(100 <= c <= 599 for c in parsed):
                raise ValueError("Status codes must be between 100-599")
            return parsed
        except ValueError as e:
            print_error(f"Invalid status codes: {e}")
            raise typer.Exit(code=1)

    def parse_methods(m: str) -> list[str]:
        valid = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        try:
            parsed = [x.strip().upper() for x in m.split(',')]
            if not all(x in valid for x in parsed):
                raise ValueError(f"Must be one of: {', '.join(valid)}")
            return parsed
        except ValueError as e:
            print_error(f"Invalid methods: {e}")
            raise typer.Exit(code=1)

    def load_rules(file_path: str) -> list[TrafficRule]:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
                rules = []
                for r in data:
                    if not all(k in r for k in ['pattern', 'action']):
                        raise ValueError("Rules must contain 'pattern' and 'action'")
                    if r['action'] not in ['modify', 'block', 'redirect', 'mock', 'modify_response']:
                        raise ValueError(f"Invalid action type: {r['action']}")
                    rules.append(TrafficRule(**r))
                if not quiet:
                    print_info(f"Loaded {len(rules)} traffic rules from {file_path}")
                return rules
        except Exception as e:
            print_error(f"Failed to load rules file: {e}")
            raise typer.Exit(code=1)

    def display_rules(rules: list[TrafficRule], title: str = "Rules"):
        print_info(f"\n=== {title.upper()} ===")
        for i, r in enumerate(rules, 1):
            print_info(f"{i}. Pattern: {r.pattern}")
            print_info(f"   Action: {r.action}")
            if r.replacement: print_info(f"   Replacement: {r.replacement}")
            if r.headers: print_info(f"   Headers: {json.dumps(r.headers)}")
            if r.status_code: print_info(f"   Status code: {r.status_code}")
            if r.mock_response: print_info(f"   Mock response: {json.dumps(r.mock_response, indent=2)}")


    # ---------- Parse filters ----------
    status_codes_list = parse_status_codes(status_codes) if status_codes else []
    methods_list = parse_methods(methods) if methods else []
    sensitive_headers_list = parse_csv_to_list(sensitive_headers.lower(), str) or []
    block_patterns_list = parse_csv_to_list(block_patterns, str) if block_patterns else None
    target_list = [t.strip().lower() for t in targets.split(",")] if targets else []

    # ---------- Load rules ----------
    rules_list = load_rules(rules_file) if rules_file else []

    # ---------- Handle rule-related flags ----------
    if test_rules:
        if not rules_file:
            print_error("--test-rules requires --rules-file")
            raise typer.Exit(code=1)
        print_success(f"✓ Successfully validated {len(rules_list)} rules in {rules_file}")
        raise typer.Exit()

    if preview_rules and rules_list:
        display_rules(rules_list, title="Loaded Rules")
        if not quiet and not typer.confirm("\nContinue with these rules?"):
            raise typer.Exit()

    # ---------- Dry-run mode ----------
    if dry_run:
        print_info("\n=== DRY RUN MODE ===")
        print_info(f"• URL contains: {url_contains or 'Any'}")
        print_info(f"• Methods: {', '.join(methods_list) if methods_list else 'All'}")
        print_info(f"• Status codes: {', '.join(map(str, status_codes_list)) if status_codes_list else 'All'}")
        print_info(f"• Block patterns: {', '.join(block_patterns_list) if block_patterns_list else 'None'}")
        print_info(f"• Excluded domains: {', '.join(exclude) if exclude else 'None'}")
        print_info(f"• Output format: {output_format}")
        print_info(f"• Log file: {log_file or 'stdout'}")
        if rules_list:
            display_rules(rules_list, title="Rules to be applied")
        print_info("\nNo traffic will actually be intercepted (dry run mode)")
        raise typer.Exit()

    # ---------- Auto-proxy ----------
    if auto_proxy and port not in [8080, 8888] and not quiet:
        if not typer.confirm(f"⚠️  Configure system proxy to use port {port}?"):
            auto_proxy = False
            print_info("Auto-proxy configuration skipped", log=config.get("log"))
    if auto_proxy:
        if not quiet: print_info("Configuring system proxy...")
        configure_system_proxy(port)

    # ---------- SSL handling ----------
    cert_args = []
    if no_ssl:
        cert_args.append("--no-ssl")
    elif ssl_cert:
        if not os.path.exists(ssl_cert) or not os.path.isfile(ssl_cert):
            print_error(f"SSL certificate invalid: {ssl_cert}")
            raise typer.Exit(code=1)
        cert_args.extend(["--certs", ssl_cert])

    # ---------- Mode info ----------
    mode = "targeted" if target_list else "system-wide"
    if not quiet:
        print_info(f"🎯 Targeted mode: {', '.join(target_list)}" if target_list else "🌐 System-wide mode (all HTTP/S traffic)")

    # ---------- Generate mitmproxy script ----------
    script_code = INTERCEPTOR_TEMPLATE.format(
        repr(port),
        repr(url_contains) if url_contains else "None",
        repr(status_codes_list) if status_codes_list else "None",
        repr([m.upper() for m in methods_list]) if methods_list else "None",
        repr(block_patterns_list) if block_patterns_list else "None",
        repr(exclude),
        repr([h.lower() for h in sensitive_headers_list]),
        repr(max_body_length),
        repr(log_file) if log_file else "None",
        repr(output_format),
        repr(no_ssl),
        json.dumps([r.__dict__ for r in rules_list]) if rules_list else "None",
        repr(mode),
        repr(target_list),
        repr(binary_threshold),
        repr(ignore)
    )

    # ---------- Run proxy ----------
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script_code)
        script_path = tf.name

    try:
        if not quiet:
            print_info("Starting proxy interceptor... Press Ctrl+C to stop.")
            print_info(f"Configure your client to use proxy: http://localhost:{port}")

        # Run mitmdump subprocess
        cmd = ["mitmdump", "-p", str(port), "-s", script_path, *cert_args]
        if quiet:
            cmd.append("-q")
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        if not quiet:
            print_info("Proxy interceptor stopped by user.")
    finally:
        try:
            if os.path.exists(script_path):
                os.remove(script_path)
                if not quiet:
                    print_info("Cleanup complete", log=config.get("log"))
            if auto_proxy:
                restore_system_proxy()
                if not quiet:
                    print_info("System proxy restored", log=config.get("log"))
        except Exception as e:
            if not quiet:
                print_warning(f"Cleanup warning: {e}", log=config.get("log"))

        



@app.command("dirscan")
@safe_cli
def bruteforce_dirs(
    url: str = typer.Option(..., '-u', '--url', help='Target URL to brute-force'),
    word_list: str = typer.Option(..., '-F', '--filepath', help='Path to directory wordlist'),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers'),
    robots: bool = typer.Option(True,"--respect-robots",help = "Respects the robot.txt of the site"),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal | safe | smart"),
    output: str = typer.Option(None, '--output', '-o', help="Output filename for results")
):
    """Run HTTP directory brute-force against a target."""

    throttle=config["source_delay"]

    try:
        validated_url = validate_url(url)
    except Exception as e:
        print_error(f"Experienced error: {e}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)

    try:
        word_list = validate_input_file(word_list)
    except Exception as e:
        print_error(str(e), show_traceback=config.get("debug", False))
        raise typer.Exit(code=1)

    headers_dict = {}
    if headers:
        try:
            headers_dict = prepare_headers(headers)
        except Exception as e:
            print_error(f"Experienced error: {e}", show_traceback=config.get("debug"))
            raise typer.Exit(code=1)

    # --- SAFE MODE LOGIC ---
    if mode == "safe":
        with open(word_list) as f:
            lines = f.readlines()

        if len(lines) > SAFE_MODE_SETTINGS["max_wordlist_size"]:
            with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
                f.writelines(lines[:SAFE_MODE_SETTINGS["max_wordlist_size"]])
                word_list = f.name
            print_info(f"[safe-mode] Wordlist truncated to {SAFE_MODE_SETTINGS['max_wordlist_size']} entries.", log=config["log"])
        
    if robots:
        disallowed_paths = get_robots_disallowed_paths(validated_url)
        if disallowed_paths:
            print_info(f"[robots.txt] Filtering {len(disallowed_paths)} disallowed paths from wordlist.", log=config["log"])
            with open(word_list) as f:
                original_lines = f.readlines()
            filtered_lines = [line for line in original_lines if not any(line.strip().startswith(path.lstrip('/')) for path in disallowed_paths)]
            with NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.writelines(filtered_lines)
                word_list = tmp.name

    # --- SMART MODE LOGIC ---
    if mode == "smart":
        max_workers = min(3, config['workers'])
        min_delay = max(2, config['min_delay'])
        max_delay = max(4, config['max_delay'])

        throttle = auto_tune_rate_limits(validated_url)

        print_info("[smart-dirscan] Crawling target for path hints...")
        prefixes = extract_path_prefixes_from_html(validated_url,headers=prepare_headers(),
                                                   throttle=throttle,timeout=config["timeout"],
                                                   verify_ssl=config["verify_ssl"],allow_redirects=True,
                                                   log=config["log"],retries=3)
        if prefixes:
            print_info(f"[smart-dirscan] Found {len(prefixes)} prefixes: {prefixes}")
            with open(word_list) as f:
                original_words = [line.strip() for line in f.readlines()]
            smart_words = [f"{prefix}{word}" for prefix in prefixes for word in original_words]
            all_words = list(set(original_words + smart_words))
            with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
                f.write('\n'.join(all_words))
                word_list = f.name
        
    if output:
        filename = output
    else:
        filename = f"dirscan_{urlparse(validated_url).netloc}_results.{config['file_format']}"

    result = http_dir_bruteforcer(
        word_list=word_list,
        url=validated_url,
        throttle=throttle,
        rmin_throttle=config["min_delay"],
        rmax_throttle=config["max_delay"],
        headers=headers_dict,
        timeout=float(config.get("timeout") or 10),
        workers=config['workers'],
        file_format=config['file_format'],
        verify_ssl=config['verify_ssl'],
        filename = filename
    )

    for key, val in result.items():
        print_success(f"{key}: {val}", log=config.get("log"))


"""
Metric Scanning
"""
@app.command('metric', help="Scans for metric/debug endpoints on a target.")
def metricprobe(
    url: str = typer.Option(None, '-u', '--url'),
    list: str = typer.Option(None, help="Path to file with list of target URLs"),
    output: str = typer.Option(None, '--output', '-o'),
    scan_mode: str = typer.Option("normal", "--scan-mode",help="Scan mode: normal | safe | smart"),
    headers: str = typer.Option(None, '-H', '--headers'),
    timeout: int = typer.Option(None, '-t', '--timeout')
):
    
    headers = prepare_headers(headers) if headers else prepare_headers()

    # Apply mode-based throttling and config overrides
    max_threads = config["workers"]
    throttle = config["source_delay"]
    timeout = float(timeout) if timeout or float(config.get("timeout")) else 10.0
    allow_redirects = True

    if scan_mode == "safe":
        
        max_threads = min(3, config["workers"])
        throttle = max(2, throttle)
        allow_redirects = False
        print_info("[safe-mode] Adjusted thread count and throttle for stealth scanning.")

    elif scan_mode == "smart":
        if url:
            throttle = auto_tune_rate_limits(url)
        elif list:
            try:
                filepath = validate_input_file(list)
                with open(filepath, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                if urls:
                    throttle = auto_tune_rate_limits(urls[0])
            except Exception as e:
                print_error(f"[smart-mode] Could not auto-tune due to error: {e}")
                raise typer.Exit(code=1)


    try:
        if url:
            url = validate_url(url.strip())
            if not url:
                print_error(f"Invalid URL: {url}")
                raise typer.Exit(code=1)

            results = scan_target(
                url,
                max_threads=max_threads,
                headers=headers,
                throttle=throttle,
                timeout=timeout,
                verify_ssl=config["verify_ssl"],
                allow_redirects=allow_redirects
            )

            if output:
                save_to_file(output, results)

        elif list:
            filepath = validate_input_file(list)
            with open(filepath, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]

            results = batch_metric_probe(
                targets,
                max_threads=max_threads,
                headers=headers,
                throttle=throttle,
                timeout=timeout,
                verify_ssl=config["verify_ssl"],
                allow_redirects=allow_redirects
            )

            if output:
                save_to_file(output, results)

        else:
            print_error("Please provide --url or --list.")
            raise typer.Exit(code=1)

    except Exception as e:
        print_error(f"Metric scan failed: {e}")
        raise typer.Exit(code=1)


def load_disallowed_subs(path: str) -> set:
    try:
        with open(path) as f:
            return set(line.strip().lower() for line in f if line.strip())
    except Exception as e:
        print_error(f"Failed to load disallowed subdomains file: {e}", show_traceback=config.get("debug"))
        return set()


def is_disallowed(sub: str, disallowed: set) -> bool:
    return sub.lower() in disallowed


@app.command("subenum", help="Finds subdomains for a given domain using multiple sources.")
def find_subdomains(
    domain: str = typer.Argument(...),
    recursive: bool = typer.Option(False, "--recursive", "-r"),
    max_depth: int = typer.Option(1, "--depth", "-d"),
    headers: str = typer.Option(None, '-H', '--headers'),
    disallowed_subs: Optional[str] = typer.Option(None, "--disallowed-subs"),
    output: str = typer.Option(None, '--output', '-o'),
    scan_mode: str = typer.Option("normal", "--scan-mode",help="Scan mode: normal | safe | smart"),
):
    
    """
    Find subdomains for a domain using multiple online sources.
    """
    throttle = config["source_delay"]

    if not is_valid_domain(domain):
        print_error(f'Invalid domain: {domain}', show_traceback=config.get("debug"))
        raise typer.Exit(code=1)

    # Set default values
    max_workers = config["workers"]
    throttle = config["source_delay"]
    timeout = float(config.get("timeout") or 10)
    verify_ssl = config["verify_ssl"]
    file_format = config["file_format"]

    save_file = output is not None

    if scan_mode == "safe":
        print_info("[safe-mode] Applying stealth constraints...")
        max_workers = min(3, max_workers)
        throttle = max(2, throttle)
        recursive = False
        max_depth = 1

    elif scan_mode == "smart":
        print_info("[smart-mode] Auto-tuning scan delays based on RTT...")
        try:
            throttle = auto_tune_rate_limits(f"https://{domain}")
        except Exception:
            print_info("[smart-mode] HTTPS failed, retrying with HTTP...")
            throttle = auto_tune_rate_limits(f"http://{domain}")

    # Perform subdomain enumeration
    try:
        result = subdomain_finder(
            domain=domain,
            timeout=timeout,
            verify_ssl=verify_ssl,
            headers=prepare_headers(headers),
            throttle=throttle,
            max_workers=max_workers,
            save_file=save_file,
            file_format=file_format,
            recursive=recursive,
            max_depth=max_depth,
            filename=output
        )

        subdomains = result.get('subdomains', [])

        if disallowed_subs:
            disallowed_set = load_disallowed_subs(disallowed_subs)
            subdomains = [sub for sub in subdomains if not is_disallowed(sub, disallowed_set)]

        for sub in subdomains:
            print_success(sub, log=config.get("log"))

        if result.get('failures'):
            print_error("\n[!] Failures:")
            for src, error in result['failures'].items():
                print_info(f"- {src}: {error}", log=config["log"])

    except Exception as e:
        print_error(f"Subdomain scan failed: {e}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)

@app.command("batch", help="Run subdomain enumeration on multiple domains from a file.")
def find_from_file(
    file: str = typer.Argument(..., help="File containing domains (one per line)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Enable recursive subdomain search"),
    max_depth: int = typer.Option(1, "--depth", "-d", help="Max recursion depth"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers'),
    output: str = typer.Option(None, '--output', '-o', help="Output filename"),
    disallowed_subs: Optional[str] = typer.Option(None, "--disallowed-subs", help="File with subdomains to exclude"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    
    try:
        file = validate_input_file(file)
    except Exception as e:
        print_error(str(e), show_traceback=config.get('debug'))
        raise typer.Exit(code=1)

    with open(file) as f:
        domains = [line.strip() for line in f if line.strip()]

    # Adjust scan parameters based on scan_mode
    throttle = config["source_delay"]
    max_workers = config["workers"]
    min_delay = config["min_delay"]
    max_delay = config["max_delay"]

    if scan_mode == "safe":
        print_info("[safe-mode] Applying stealth constraints...", log=config.get("log"))
        max_domains = SAFE_MODE_SETTINGS["max_domains"]
        if len(domains) > max_domains:
            print_info(f"[safe-mode] Domain list trimmed to first {max_domains} entries.", log=config["log"])
            domains = domains[:max_domains]
        recursive = False
        max_depth = 1
        max_workers = min(3, max_workers)
        min_delay = max(2, min_delay)
        max_delay = max(4, max_delay)

    elif scan_mode == "smart" and domains:
        print_info("[smart-mode] Auto-tuning delays based on RTT from first domain...", log=config.get("log"))
        throttle = auto_tune_rate_limits(f"https://{domains[0]}")  # Uses first domain for RTT

    save_file = output is not None

    results = subdomain_from_file(
        filename=file,
        max_workers=max_workers,
        headers=prepare_headers(headers),
        throttle = throttle,
        recursive=recursive,
        max_depth=max_depth,
        save_file=save_file,
        file_format=config['file_format'],
        rmin_throttle=min_delay,
        rmax_throttle=max_delay,
        output=output
    )

    disallowed_set = load_disallowed_subs(disallowed_subs) if disallowed_subs else set()

    for domain, subs in results.items():
        print_success(f"\n[+] {domain}", log=config.get("log"))
        filtered = [sub for sub in subs if not is_disallowed(sub, disallowed_set)]
        for sub in filtered:
            print_success(f"    {sub}", log=config.get("log"))


@app.command("wordlist")
@safe_cli
def create_custom_wordlist(
    domain: str = typer.Argument(..., help="Target domain (e.g. http://localhost:3000)"),
    wordlist_path: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Optional wordlist file (for subdomain mode)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output filename"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional custom headers as JSON string'),
    mode: str = typer.Option('subdomain', '--mode', help="Wordlist mode: 'subdomain' or 'content'"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    """
    Generate a custom wordlist by scraping the target site (supports 'subdomain' or 'content' modes).
    """
    throttle = config["source_delay"]


    # Validate input wordlist for subdomain mode
    if wordlist_path and mode == 'subdomain':
        try:
            wordlist_path = validate_input_file(wordlist_path)
        except Exception as e:
            print_error(str(e), show_traceback=config.get('debug'))
            raise typer.Exit(code=1)

        # Safe mode: truncate large wordlist
        if scan_mode == "safe":
            with open(wordlist_path) as f:
                lines = f.readlines()
            if len(lines) > SAFE_MODE_SETTINGS["max_wordlist_size"]:
                with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
                    f.writelines(lines[:SAFE_MODE_SETTINGS["max_wordlist_size"]])
                    wordlist_path = f.name
                print_info(f"[safe-mode] Wordlist truncated to {SAFE_MODE_SETTINGS['max_wordlist_size']} entries.",
                           log=config["log"])

    # Smart mode: auto-tune delays
    if scan_mode == "smart":
        throttle = auto_tune_rate_limits(domain)

    
    # Set default output filename if saving
    save_file = output is not None

    headers_dict = prepare_headers(headers)

    # Smart content-mode: inject extracted content into wordlist
    if scan_mode == "smart" and mode == "content":
        print_info("[smart-wordlist] Crawling target to extract path segments for enrichment...")
        prefixes = extract_path_prefixes_from_html(domain,headers=prepare_headers(),
                                                   throttle=throttle,timeout=float(config.get("timeout") or 10),
                                                   verify_ssl=config["verify_ssl"],allow_redirects=True,
                                                   log=config["log"],retries=3)
        if prefixes:
            print_info(f"[smart-wordlist] Found {len(prefixes)} content path segments: {prefixes}", log=config["log"])
            with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
                f.write("\n".join(prefixes))
                wordlist_path = f.name

    # Generate wordlist
    results = generate_custom_wordlist(
        domain=domain,
        wordlist_path=wordlist_path,
        throttle=throttle,
        headers=headers_dict,
        save_file=save_file,
        filename=output,
        file_format=config['file_format'],
        verify_ssl=config["verify_ssl"],
        timeout=float(config.get("timeout") or 10),
        mode=mode
    )

    # Print results
    for item in sorted(results):
        typer.secho(item, fg=typer.colors.GREEN)


def get_domain_from_url(url: str) -> str:
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
    return parsed.netloc.split(':')[0]

def auto_fix_url_protocol(url: str) -> str:
    from socket import gethostbyname
        
    try:

        domain = get_domain_from_url(url)
        gethostbyname(domain)
    
    except Exception:
        print_error("Domain does not resolve.", show_traceback=config.get('debug'))
        raise typer.Exit(code = 1)

    if not url.startswith(("http://", "https://")):
        https_url = "https://" + url
        try:
            resp = requests.head(https_url, headers=prepare_headers(), timeout=float(config.get("timeout") or 10)
                                 , verify=config["verify_ssl"])
            if resp.status_code < 400:
                return https_url
        except Exception:
            print_info(f"[!] HTTPS failed, falling back to HTTP: {url}", log=config.get("log"))
        return "http://" + url

    return url


def save_results(hostname: str, prefix: str, data: dict):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = config['file_format']
    filename = f"{hostname}_{prefix}_{timestamp}.{ext}"
    save_to_file(filename, data)


@app.command(help="Detect technologies and SSL/TLS used by a website.")
@safe_cli
def techfingerprint(
    url: str = typer.Option(None, "--url", "-u", help="Target URL to analyze"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Optional output filename"),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="Optional content to analyze (for testing purposes)"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    try:
        
        throttle_delay = float(config.get("source_delay") or 1)
        verify_ssl = config["verify_ssl"]
        timeout = float(config.get("timeout") or 10)
        ssl_info = None

        # Apply scan mode behavior
        if scan_mode == "safe":
            print_info("[safe-mode] SSL check disabled. Throttle increased.", log=config["log"])
            ssl_info = None
            throttle_delay = max(throttle_delay, 2)
        elif scan_mode == "smart" and url:
            print_info("[smart-mode] Tuning delay based on RTT...", log=config["log"])
            throttle_delay = auto_tune_rate_limits(url)

        # Handle content override
        if content:
            if os.path.isfile(content):
                with open(content, 'r') as f:
                    content = f.read()
            elif not isinstance(content, str):
                raise ValueError("Content must be a string or a valid file path.")
            content = content.strip()
        else:
            if not validate_url(url):
                raise SyntaxError("Not a valid URL.")
            url = auto_fix_url_protocol(url)

            headers, cookies, content = get_headers_cookies(
                url,
                headers=prepare_headers(),
                throttle=throttle_delay,
                verify_ssl=verify_ssl,
                timeout=timeout
            )

        headers, cookies, content = headers or {}, cookies or {}, content or ''

        # Fingerprint technologies
        tech_stack = get_tech_stack(headers=headers, cookies=cookies, content=content)

        # SSL Info if allowed
        if ssl_info is None and url and scan_mode != "safe":
            parsed = urlparse(url)
            if parsed.scheme != "https":
                print_info(f"Skipping SSL check: {url} is not HTTPS.", log=config["log"])
            else:
                ssl_info = get_ssl_info(url, timeout=timeout)
                if not ssl_info:
                    print_info(f"[!] No SSL/TLS info found for {url}.", log=config["log"])

        # Format output
        output_lines = ["\n[+] Technology Stack:"]
        for category, techs in tech_stack.items():
            output_lines.append(f"- {category}:")
            for tech in techs:
                output_lines.append(f"  • {tech}")

        if ssl_info:
            output_lines.append("\n[+] SSL/TLS Info:")
            for key, value in ssl_info.items():
                output_lines.append(f"- {key}: {value}")

        output_text = "\n".join(output_lines)
        print_success(output_text, log=config.get("log"))

        # Save result
        if output:
            hostname = urlparse(url).hostname if url else "local_content"
            data_to_save = {"tech_stack": tech_stack, "ssl_info": ssl_info}
            if output:
                save_to_file(output, data_to_save)
            else:
                save_results(hostname, "techfingerprint", data_to_save)

    except SyntaxError as se:
        print_error(f"Received error: {se}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)
    except Exception as e:
        print_error(f"Experienced error: {e}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)



@lru_cache(maxsize=1)
def load_cve_data_once():
    init_cve_db(CVE_DB_PATH)
    files = list_files_in_folder('cves_jsons')
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def import_cve_worker(file):
        try:
            import_cves_from_json(file, "cves.db")
            return f"Imported {file}"
        except Exception as e:
            return f"Failed to import {file}: {e}"

    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        futures = [executor.submit(import_cve_worker, file) for file in files]
        for future in as_completed(futures):
            result = future.result()
            print_info(result, log=config.get("log"))


@app.command(help="Scan the target's tech stack for known CVEs.")
@safe_cli
def cvescan(
    url: str,
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Optional output filename"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    try:
        load_cve_data_once()  # Only initialize CVE DB here

        if not validate_url(url):
            raise SyntaxError("Not a valid URL.")
        url = auto_fix_url_protocol(url)

        
        # Ensure throttle has a valid value
        throttle_delay = config["source_delay"]
        verify_ssl = config.get("verify_ssl", True)
        timeout = float(config.get("timeout", 10.0))  
        ssl_info = None

        if scan_mode == "safe":
            print_info("[safe-mode] SSL/TLS check disabled. Throttle increased.", log=config["log"])
            ssl_info = None
            throttle_delay = max(throttle_delay, 2)
        elif scan_mode == "smart":
            print_info("[smart-mode] Tuning delay based on RTT...", log=config["log"])
            throttle_delay = auto_tune_rate_limits(url)

        # Collect headers, cookies, content
        headers, cookies, content = get_headers_cookies(
            url,
            headers=prepare_headers(),
            verify_ssl=verify_ssl,
            throttle=throttle_delay,
            timeout=timeout
        )

        # if not all([headers, cookies, content]):
        #     raise ValueError("Failed to fetch headers, cookies, or content.")

        tech_stack = get_tech_stack(headers=headers, cookies=cookies, content=content)

        if scan_mode != "safe":
            parsed = urlparse(url)
            if parsed.scheme == "https":
                ssl_info = get_ssl_info(url, timeout=timeout)
                if not ssl_info:
                    print_info(f"[!] No SSL/TLS info found for {url}.", log=config["log"])
            else:
                print_info("Skipping SSL check: Not an HTTPS target.", log=config["log"])
        else:
            print_info("[safe-mode] Skipping SSL/TLS info gathering.", log=config["log"])

        # Flatten tech list and scan CVEs
        flat_techs = sum(tech_stack.values(), [])
        results = scan_for_cves_local(flat_techs)

        # Output to CLI
        output_lines = []

        if results:
            output_lines.append("\n[+] CVE Results:")
            for tech, cves in results.items():
                output_lines.append(f"- {tech}:")
                for cve in cves:
                    output_lines.append(f"  • {cve['id']}: {cve['summary']}")
        else:
            output_lines.append("[!] No CVEs found – maybe due to missing version info or unknown tech.")

        if ssl_info:
            output_lines.append("\n[+] SSL/TLS Info:")
            for key, value in ssl_info.items():
                output_lines.append(f"- {key}: {value}")

        output_text = "\n".join(output_lines)
        print_success(output_text, log=config.get("log"))

        # Save results if needed
        if output:
            hostname = urlparse(url).hostname or "output"
            save_data = {
                "cve_results": results,
                "ssl_info": ssl_info
            }
            if output:
                save_to_file(output, save_data)
            else:
                save_results(hostname, "cvescan", save_data)

    except SyntaxError as se:
        print_error(f"Received error: {se}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)
    except Exception as e:
        print_error(f"Experienced error: {e}", show_traceback=config.get("debug"))
        raise typer.Exit(code=1)


def clear_console():
    os.system('cls' if platform.system() == 'Windows' else 'clear')


@app.command("update-cves", help="Download and import latest NVD CVE JSON feeds into the local DB.")
@safe_cli
def update_cve_data():

    cve_folder = "cves_jsons"
    os.makedirs(cve_folder, exist_ok=True)

    current_year = datetime.now().year
    NVD_1_1_FEEDS = [
        f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        for year in range(2002, current_year + 1)
    ] + [
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
    ]


    print_info(f" Downloading CVE JSON feeds ({len(NVD_1_1_FEEDS)} files)...", log=config["log"])

    failed_downloads = []
    lock = threading.Lock()

    def download_cve_file(url):
        filename = url.split("/")[-1].replace(".gz", "")
        gz_path = os.path.join(cve_folder, filename + ".gz")
        json_path = os.path.join(cve_folder, filename)

        try:
            headers = {"User-Agent": "ReconKit/2.0"}
            resp = fetch_with_retry(
                url,
                headers=headers,
                timeout=config["timeout"],
                verify_ssl=config["verify_ssl"],
                allow_redirects=True,
                throttle=config["source_delay"],
            )

            if resp and resp.status_code == 200:
                with open(gz_path, "wb") as f:
                    f.write(resp.content)

                try:
                    with gzip.open(gz_path, "rb") as f_in:
                        with open(json_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(gz_path)
                    return (filename, "success")
                except Exception as gzerr:
                    os.remove(gz_path)
                    raise RuntimeError(f"Decompression failed: {gzerr}")
            else:
                code = resp.status_code if resp else "No response"
                with lock:
                    failed_downloads.append((filename, f"HTTP {code}"))
                return (filename, "skipped")
        except Exception as e:
            with lock:
                failed_downloads.append((filename, f"Exception: {e}"))
            return (filename, "error")

    # Parallel downloading
    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        futures = {executor.submit(download_cve_file, url): url for url in NVD_1_1_FEEDS}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading CVEs"):
            fname, status = future.result()
            if status == "success":
                tqdm.write(f"[✅]  Updated {fname}")
                log_to_file(f"Updated {fname}", level="info")
            elif status == "skipped":
                tqdm.write(f"[⏩]  Skipped {fname}")
                log_to_file(f"Skipped {fname}", level="debug")
            else:
                tqdm.write(f"[❌] Failed {fname}")
                log_to_file(f"Failed {fname}", level="error")

    clear_console()

    # Import CVEs
    print_info(" Importing CVEs into the database...", log=config["log"])

    failed_names = {f[0] for f in failed_downloads}
    files_to_import = [f for f in list_files_in_folder(cve_folder) if f not in failed_names]

    def import_worker(file):
        try:
            import_cves_from_json(file, "cves.db")
            return (file, "ok")
        except Exception as e:
            return (file, f"import_error: {e}")

    # Import in parallel
    import_errors = []
    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        futures = {executor.submit(import_worker, f): f for f in files_to_import}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Importing to DB"):
            fname, status = future.result()
            if status == "ok":
                tqdm.write(f"[📥]  Imported {fname}")
            else:
                import_errors.append((fname, status))

    print_success("[✅] CVE database update complete.", log=config["log"])

    # Show any failures
    if failed_downloads or import_errors:
        print_warning("\n[!] Some issues occurred during update:", log=config["log"])

        if failed_downloads:
            print_warning(f"[🚫] - Download failures ({len(failed_downloads)}):")
            for fname, reason in failed_downloads:
                print_warning(f"   • {fname} → {reason}")

        if import_errors:
            print_warning(f"[🚫] - Import errors ({len(import_errors)}):")
            for fname, reason in import_errors:
                print_warning(f"   • {fname} → {reason}")

        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
