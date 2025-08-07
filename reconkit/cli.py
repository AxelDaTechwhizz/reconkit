"""
RECONKIT TOOL WITH:
    - HTTP DIRBRUTE
    - SUBDOMAIN ENUMERATION
    - TECH FINGERPRINTING
    - CVE SCANNER
"""

import typer, requests, os, platform, threading, gzip, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from deepdiff import DeepDiff
from functools import lru_cache
from reconkit.modules.cvescanner import scan_for_cves_local,init_cve_db,import_cves_from_json
from urllib.parse import urlparse,urljoin
from datetime import datetime
from typing import Optional
from functools import wraps
from tempfile import NamedTemporaryFile
from reconkit.modules.dirbrute import http_dir_bruteforcer,extract_path_prefixes_from_html
from reconkit.modules.techfingerprint import get_headers_cookies, get_tech_stack, get_ssl_info
from reconkit.modules.config import load_user_config, save_user_config, DEFAULT_CONFIG_PATH
from reconkit.modules.utils import (
    validate_url,print_error,print_success,print_warning,print_info,is_valid_domain,
    validate_input_file,save_to_file,list_files_in_folder,fetch_with_retry,
    log_to_file)
from reconkit.modules.subdomain import (
    subdomain_finder,
    subdomain_from_file,
    generate_custom_wordlist
)

app = typer.Typer(help="ReconKit: A modular recon tool for dir brute-force, subdomain enum, tech detection, and CVE scanning.")
app.pretty_exceptions_enabled = True  # Enable pretty exceptions for better error handling

CVE_DB_PATH = "cves.db"


config = load_user_config()

SAFE_MODE_SETTINGS = {
    "max_wordlist_size": 500,   # Max number of lines to use from wordlist
    "max_domains": 10,          # Max domains to process in batch mode
    "no_recursive_subdomains": True,  # Disable recursive by default
    "limit_tech_stack": True    # Don't run SSL info or deep matching
}

__version__ = "2.0.0"

def print_version_and_exit(value: bool):
    if value:
        print_success(f"ReconKit version {__version__}", log=config.get("log"))
        raise typer.Exit()


def safe_cli(f):
    @wraps(f)  # ← critical to preserve signature
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            print_error(f"Experienced error: {e}", show_traceback=config.get("debug"))
            raise typer.Exit(code=1)
    return wrapper

import time

def auto_tune_rate_limits(url: str):
    """Measure average response speed using fetch_with_retry, and auto-tune scan delay accordingly."""
    try:
        delays = []
        headers = {}
        verify_ssl = config['verify_ssl']
        timeout = config['timeout']
        throttle = config.get('source_delay', 0.5)

        for _ in range(5):
            start = time.time()
            response = fetch_with_retry(
                url=url,
                headers=headers,
                timeout=timeout,
                verify_ssl=verify_ssl,
                allow_redirects=True,
                throttle=throttle,
                retries=3
            )
            elapsed = time.time() - start

            if response and response.status_code < 400:
                delays.append(elapsed)

        if not delays:
            print_warning("[smart-dirscan] No valid responses received for tuning.")
            return

        avg = sum(delays) / len(delays)

        # Adjust throttle based on average
        if avg > 2.0:
            config['source_delay'] = 4
        elif avg > 1.0:
            config['source_delay'] = 2
        elif avg > 0.5:
            config['source_delay'] = 1
        else:
            config['source_delay'] = 0

        print_info(f"[smart-dirscan] Auto-tuned source delay to {config['source_delay']}s (avg: {avg:.2f}s)", log=config['log'])

    except Exception as e:
        print_warning(f"[smart-dirscan] Auto-tuning failed: {e}")



def prepare_headers(input_headers: Optional[str] = None) -> dict:
    headers_dict = {}

    # Parse semi-colon-separated headers
    if input_headers:
        for item in input_headers.split(';'):
            if ':' in item:
                key, value = item.strip().split(':', 1)
                headers_dict[key.strip()] = value.strip()

    # Set default User-Agent if missing
    headers_dict.setdefault("User-Agent", "ReconKit/2.0")

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

def apply_profile(profile_name: str, log: bool):
    if profile_name == "bugbounty-vidaxl":
        print_info("[*] Profile 'bugbounty-vidaxl' activated.", log=config["log"])
        config.update({
            'workers': 2,
            'source_delay': 3.0,
            'min_delay': 2.0,
            'max_delay': 6.0,
            'safe_mode': True,
            'disable_dirbrute': True
        })

    elif profile_name == "yeswehack-dojo":
        print_info("[*] Profile 'yeswehack-dojo' activated.", log=config["log"])
        config.update({
            'workers': 1,
            'source_delay': 3.0,
            'min_delay': 1.0,
            'max_delay': 5.5,
            'safe_mode': True,
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
def callback(ctx : typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the version and exit",
        is_flag=True,
        callback=print_version_and_exit,
        expose_value=False,  # Don't pass this as argument to commands
    ),
    timeout: int = typer.Option(20, '-t', '--timeout', help='Request timeout (in seconds)'),
    workers: int = typer.Option(10, '-w', '--workers', help='Number of threads to execute task'),
    file_format: str = typer.Option('txt', '-f', '--format', help='File format to save results (txt, csv, json)'),
    throttle: float = typer.Option(1.0, '-th', '--throttle', help='Base wait time between sources'),
    throttle_min: float = typer.Option(1.0, '-tm', '--throttle-min', help='Minimum delay (rate limit buffer)'),
    throttle_max: float = typer.Option(4.0, '-tx', '--throttle-max', help='Maximum delay (rate limit buffer)'),
    verify_ssl: bool = typer.Option(True, '-s', '--verify-ssl', help='Verify SSL certificates'),
    save_file: bool = typer.Option(False, '-S', '--savefile', help='Save output to file'),
    debug: bool = typer.Option(False, '--debug', help='Show full error tracebacks for debugging'),
    log : bool = typer.Option(False,'--log', help = "Log output messages to file.\n i.e. error messages log by default"),
    profile: Optional[str] = typer.Option(None, '--profile', '-p', help='Use a predefined scan profile (e.g., bugbounty-vidaxl)'),
    save_conf: bool = typer.Option(False, "--save-config", help="Save current settings to defaults.json"),
    support : bool = typer.Option(False,'--support', help = "Show some support to a guy who lives on coffee and prayers xD.\nGod bless you!! :) ")
    ):

    ensure_data_dirs()
    
    if support:
        show_support()
    
    show_warning_message(ctx)

    if profile == "bugbounty-vidaxl":
        config.update({
            'profile': profile
        })
        apply_profile(profile_name=profile,log=log)
    
    if version:
        print_version_and_exit()

    cli_config= {
        "timeout": timeout,
        "workers": workers,
        "file_format": file_format,
        "source_delay": throttle,
        "min_delay": throttle_min,
        "max_delay": throttle_max,
        "verify_ssl": verify_ssl,
        "save_file": save_file,
        "debug": debug,
        "log": log,
        "profile" : profile
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


@app.command("dirscan")
@safe_cli
def bruteforce_dirs(
    url: str = typer.Option(..., '-u', '--url', help='Target URL to brute-force'),
    word_list: str = typer.Option(..., '-F', '--filepath', help='Path to directory wordlist'),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers'),
    mode: str = typer.Option("normal", "--mode", help="Scan mode: normal | safe | smart"),
    output: str = typer.Option(None, '-o', help="Output filename for results")
):
    """Run HTTP directory brute-force against a target."""

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

        if config.get("respect_robots"):
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
        auto_tune_rate_limits(validated_url)

        print_info("[smart-dirscan] Crawling target for path hints...")
        prefixes = extract_path_prefixes_from_html(validated_url)
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
        throttle=config["source_delay"],
        rmin_throttle=config["min_delay"],
        rmax_throttle=config["max_delay"],
        headers=headers_dict,
        timeout=config['timeout'],
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
    url: str = typer.Option(None, '-u', '--url', help="Target base URL"),
    list: str = typer.Option(None, help="Path to file with list of target URLs"),
    output: str = typer.Option(None, '-o', help="Output filename for results"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    """
    Scan for exposed metric/debug endpoints.
    """

    # Apply mode-based throttling and config overrides
    max_threads = config["workers"]
    throttle = config["source_delay"]
    timeout = config["timeout"]
    allow_redirects = True

    if scan_mode == "safe":
        max_threads = min(3, config["workers"])
        throttle = max(2, throttle)
        allow_redirects = False
        print_info("[safe-mode] Adjusted thread count and throttle for stealth scanning.")

    elif scan_mode == "smart":
        if url:
            auto_tune_rate_limits(url)
        elif list:
            try:
                filepath = validate_input_file(list)
                with open(filepath, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                if urls:
                    auto_tune_rate_limits(urls[0])
            except Exception as e:
                print_error(f"[smart-mode] Could not auto-tune due to error: {e}")
                raise typer.Exit(code=1)

    headers = prepare_headers()

    try:
        if url:
            url = validate_url(url.strip())
            if not url:
                print_error(f"Invalid URL: {url}")
                raise typer.Exit(code=1)

            results = metricprobe.scan_target(
                url,
                max_threads=max_threads,
                headers=headers,
                throttle=throttle,
                timeout=timeout,
                verify_ssl=config["verify_ssl"],
                allow_redirects=allow_redirects
            )

            if output and results:
                save_to_file(output, results)

        elif list:
            filepath = validate_input_file(list)
            with open(filepath, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]

            results = metricprobe.batch_metric_probe(
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
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Enable recursive subdomain search"),
    max_depth: int = typer.Option(1, "--depth", "-d", help="Max recursion depth"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers'),
    disallowed_subs: Optional[str] = typer.Option(None, "--disallowed-subs", help="File with subdomains to exclude"),
    output: str = typer.Option(None, '-o', help="Output filename for results"),
    scan_mode: str = typer.Option("normal", "--scan-mode", help="Scan mode: normal | safe | smart")
):
    """
    Find subdomains for a domain using multiple online sources.
    """

    if not is_valid_domain(domain):
        print_error(f'Invalid domain: {domain}', show_traceback=config.get("debug"))
        raise typer.Exit(code=1)

    # Set default values
    max_workers = config["workers"]
    throttle = config["source_delay"]
    timeout = config["timeout"]
    verify_ssl = config["verify_ssl"]
    file_format = config["file_format"]

    if output: 
        save_file = True

    if scan_mode == "safe":
        print_info("[safe-mode] Applying stealth constraints...")
        max_workers = min(3, max_workers)
        throttle = max(2, throttle)
        recursive = False
        max_depth = 1

    elif scan_mode == "smart":
        print_info("[smart-mode] Auto-tuning scan delays based on RTT...")
        auto_tune_rate_limits(f"https://{domain}")

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
        auto_tune_rate_limits(f"https://{domains[0]}")  # Uses first domain for RTT

    results = subdomain_from_file(
        filename=file,
        max_workers=max_workers,
        headers=prepare_headers(headers),
        recursive=recursive,
        max_depth=max_depth,
        save_file=config['save_file'],
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
        auto_tune_rate_limits(domain)

    
    # Set default output filename if saving
    if output:
        save_file = True
    else:
        save_file = False

    headers_dict = prepare_headers(headers)

    # Smart content-mode: inject extracted content into wordlist
    if scan_mode == "smart" and mode == "content":
        print_info("[smart-wordlist] Crawling target to extract path segments for enrichment...")
        prefixes = extract_path_prefixes_from_html(domain)
        if prefixes:
            print_info(f"[smart-wordlist] Found {len(prefixes)} content path segments: {prefixes}", log=config["log"])
            with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
                f.write("\n".join(prefixes))
                wordlist_path = f.name

    # Generate wordlist
    results = generate_custom_wordlist(
        domain=domain,
        wordlist_path=wordlist_path,
        throttle=config["source_delay"],
        headers=headers_dict,
        save_file=save_file,
        filename=output,
        file_format=config['file_format'],
        verify_ssl=config["verify_ssl"],
        timeout=config["timeout"],
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
            resp = requests.head(https_url, headers=prepare_headers(), timeout=config["timeout"], verify=config["verify_ssl"])
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
        headers, cookies = {}, {}
        throttle_delay = config["source_delay"]
        verify_ssl = config["verify_ssl"]
        timeout = config["timeout"]
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

    with ThreadPoolExecutor(max_workers=5) as executor:
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

        # Determine scan behavior
        throttle_delay = config["source_delay"]
        verify_ssl = config["verify_ssl"]
        timeout = config["timeout"]
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

        if not all([headers, cookies, content]):
            raise ValueError("Failed to fetch headers, cookies, or content.")

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
        f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}{suffix}.json.gz"
        for year in range(2002, current_year + 1)
        for suffix in ("", "-modified")
    ] + [
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
    ]

    print_info(f" Downloading CVE JSON feeds ({len(NVD_1_1_FEEDS)} files)...", log=config["log"])

    failed_downloads = []
    lock = threading.Lock()

    def download_cve_file(url):
        filename = url.split("/")[-1].replace(".gz", "")
        gz_path = os.path.join(cve_folder, filename + ".gz")
        json_path = os.path.join(cve_folder, filename)

        try:
            headers = {"User-Agent": "ReconKit/1.0"}
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
            return (file, "[✅] ok")
        except Exception as e:
            return (file, f"[❌] import_error: {e}")

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

