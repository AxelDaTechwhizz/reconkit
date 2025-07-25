"""
RECONKIT TOOL WITH:
    - HTTP DIRBRUTE
    - SUBDOMAIN ENUMERATION
    - TECH FINGERPRINTING
    - CVE SCANNER
"""

import typer
import requests
import os
from reconkit.modules.cvescanner import scan_for_cves_local,init_cve_db,import_cves_from_json
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional
from functools import wraps
from reconkit.modules.dirbrute import http_dir_bruteforcer
from reconkit.modules.techfingerprint import get_headers_cookies, get_tech_stack, get_ssl_info
from reconkit.modules.utils import (
    validate_url,print_error,print_success,print_info,is_valid_domain,
    validate_input_file,save_to_file,list_files_in_folder,fetch_with_retry)
from reconkit.modules.subdomain import (
    subdomain_finder,
    subdomain_from_file,
    generate_custom_wordlist
)

app = typer.Typer(help="ReconKit: A modular recon tool for dir brute-force, subdomain enum, tech detection, and CVE scanning.")
app.pretty_exceptions_enabled = True  # Enable pretty exceptions for better error handling


config = {}

SAFE_MODE_SETTINGS = {
    "max_wordlist_size": 500,   # Max number of lines to use from wordlist
    "max_domains": 10,          # Max domains to process in batch mode
    "no_recursive_subdomains": True,  # Disable recursive by default
    "limit_tech_stack": True    # Don't run SSL info or deep matching
}

__version__ = "1.0.0"

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


def prepare_headers(input_headers: Optional[str] = None) -> dict:
    headers_dict = {}

    if input_headers:
        for item in input_headers.split(';'):
            if ':' in item:
                key, value = item.strip().split(':', 1)
                headers_dict[key.strip()] = value.strip()

    # Default User-Agent if not provided
    if "User-Agent" not in headers_dict:
        headers_dict["User-Agent"] = "ReconKit/1.0"

    return headers_dict


def show_warning_message(ctx: typer.Context):
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
def callback(version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the version and exit",
        is_flag=True,
        callback=print_version_and_exit,
        expose_value=False,  # Don't pass this as argument to commands
    ),
    safe_mode: bool = typer.Option(True, '--safe-mode/--unsafe', help='Enable safe mode (default: ON)'),
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
    support : bool = typer.Option(False,'--support', help = "Show some support to a guy who lives on coffee and prayers xD.\nGod bless you!! :) ")
    ):

    ensure_data_dirs()
        # Safe mode overrides
    if safe_mode:
        print_info("[*] Safe mode enabled: reducing concurrency, increasing delays, and being stealthy.", log=log)
        workers = min(workers, 2)
        throttle = max(throttle, 5.0)
        throttle_min = max(throttle_min, 2.0)
        throttle_max = max(throttle_max, 10.0)

    if support:
        show_support()
        

    config.update({
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
        "safe_mode": safe_mode
    })

@app.command("dirscan", help = "Run HTTP directory brute-force against a target.")
@safe_cli
def bruteforce_dirs(
    url: str = typer.Option(..., '-u', '--url', help='Target URL to brute-force'),
    word_list: str = typer.Option(..., '-F', '--filepath', help='Path to directory wordlist'),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers')
    ):
    """Run HTTP directory brute-force against a target."""
    
    try:
        validated_url = validate_url(url)
    except Exception as e:
        print_error(f"Experinced error as {e}",show_traceback=config.get("debug", False))
        raise typer.Exit(code=1)
    

    try:
        validate_input_file(word_list)
    except Exception as e:
        print_error(str(e),show_traceback=config.get("debug", False))
        raise typer.Exit(code=1)

    headers_dict = {}
    if headers:
        try:
            headers_dict = prepare_headers(headers)
        except Exception as e:
            print_error(f"Experienced error as: {e}",
                         show_traceback=config.get("debug"))
            raise typer.Exit(code=1)

        if config.get("safe_mode"):
            # Trim wordlist if too large
            with open(word_list) as f:
                lines = f.readlines()

            if len(lines) > SAFE_MODE_SETTINGS["max_wordlist_size"]:
                word_list = "/tmp/safe_mode_wordlist.txt"
                with open(word_list, "w") as f:
                    f.writelines(lines[:SAFE_MODE_SETTINGS["max_wordlist_size"]])
                print_info(f"[safe-mode] Wordlist truncated to {SAFE_MODE_SETTINGS['max_wordlist_size']} entries.")


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
        save_to_file=config["save_file"]
    )

    for key, val in result.items():
        print_success(f"{key}: {val}",log = config.get("log"))
        

@app.command("subenum", help = "Find subdomains for a domain using multiple online sources.")
@safe_cli
def find_subdomains(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Enable recursive subdomain search"),
    max_depth: int = typer.Option(1, "--depth", "-d", help="Max recursion depth"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers')
):
    
    if not is_valid_domain(domain):
        print_error(f'Invalid domain: {domain}',show_traceback = config.get("debug"))
        raise typer.Exit(code=1)

    """
    Find subdomains for a domain using multiple online sources.
    """
    if config.get("safe_mode"):
        if recursive:
            print_info("[safe-mode] Recursive subdomain scan disabled.")
        recursive = False
        max_depth = 1

    result = subdomain_finder(
        domain=domain,
        headers = prepare_headers(headers),
        throttle=config["source_delay"],
        max_workers=config['workers'],
        save_file=config['save_file'],
        file_format=config['file_format'],
        recursive=recursive,
        max_depth=max_depth
    )

    for sub in result['subdomains']:
        print_success(sub,log = config.get("log"))
        

    if result.get('failures'):
        print_info("\n[!] Failures:")
        for src, error in result['failures'].items():
            print_info(f"- {src}: {error}")

@app.command("batch", help = "Run subdomain enumeration on multiple domains from a file.")
@safe_cli
def find_from_file(
    file: str = typer.Argument(..., help="File containing domains (one per line)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Enable recursive subdomain search"),
    max_depth: int = typer.Option(1, "--depth", "-d", help="Max recursion depth"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers')
):
    
    """
    Run subdomain enumeration on multiple domains from a file.
    """
    try:
        validate_input_file(file)
    except Exception as e:
        print_error(str(e),show_traceback=config.get('debug'))
        raise typer.Exit(code=1)


    with open(file) as f:
        domains = [line.strip() for line in f if line.strip()]

    if config.get("safe_mode") and len(domains) > SAFE_MODE_SETTINGS["max_domains"]:
        print_info(f"[safe-mode] Domain list trimmed to first {SAFE_MODE_SETTINGS['max_domains']} entries.")
        domains = domains[:SAFE_MODE_SETTINGS["max_domains"]]
        
        recursive = False
        max_depth = 1

    else:

        recursive = recursive
        max_depth = max_depth

    results = subdomain_from_file(filename = file,max_workers = config['workers'],
                                  headers=prepare_headers(headers),recursive = recursive,
                                    max_depth = max_depth, save_file = config['save_file'],
                                    file_format = config['file_format'],rmin_throttle = config["min_delay"],
                                    rmax_throttle = config["max_delay"])

    for domain, subs in results.items():
        print_success(f"\n[+] {domain}",log = config.get("log"))
        for sub in subs:
            print_success(f"    {sub}",log = config.get("log"))

@app.command("wordlist", help = "Generate a custom wordlist based on live scraping + optional wordlist.")
@safe_cli
def create_custom_wordlist(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    wordlist_path: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Optional wordlist file"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output filename"),
    headers: str = typer.Option(None, '-H', '--headers', help='Optional headers')
):
    """
    Generate a custom wordlist based on live scraping + optional wordlist.
    """
    try:
        if wordlist_path:
            validate_input_file(wordlist_path)
    except Exception as e:
        print_error(str(e),show_traceback=config.get('debug'))
        raise typer.Exit(code=1)

    if config.get("safe_mode"):
            # Trim wordlist if too large
            with open(wordlist_path) as f:
                lines = f.readlines()

            if len(lines) > SAFE_MODE_SETTINGS["max_wordlist_size"]:
                word_list = "/tmp/safe_mode_wordlist.txt"
                with open(wordlist_path, "w") as f:
                    f.writelines(lines[:SAFE_MODE_SETTINGS["max_wordlist_size"]])
                print_info(f"[safe-mode] Wordlist truncated to {SAFE_MODE_SETTINGS['max_wordlist_size']} entries.")


    subdomains = generate_custom_wordlist(domain,wordlist_path,prepare_headers(headers), config['save_file'],
                                           output, config['file_format'])

    for sub in sorted(subdomains):
        typer.secho(sub,fg=typer.colors.GREEN)


def auto_fix_url_protocol(url: str) -> str:
    # Check if domain resolves before trying
    from socket import gethostbyname
    try:
        gethostbyname(url.split('/')[0])
    except:
        print_error("Domain does not resolve.",show_traceback=config.get('debug'))
        raise typer.Exit(code=1)

    if not url.startswith(("http://", "https://")):
        https_url = "https://" + url
        try:
            resp = requests.head(https_url, headers = prepare_headers(),timeout=5, verify=True)
            if resp.status_code < 400:
                return https_url
        except Exception as e:
            print_info(f"[!] HTTPS failed, falling back to HTTP: {url}",log = config.get("log"))

        return "http://" + url
    return url

def save_results(hostname: str, prefix: str, data: dict):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = config['file_format']
    filename = f"results/{hostname}_{prefix}_{timestamp}.{ext}"
    save_to_file(filename, data)

@app.command(help = "Detect technologies and SSL/TLS used by a website.")
@safe_cli
def techfingerprint(url: str):
    """Detect technologies and SSL/TLS used by a website."""
    try:
        url = auto_fix_url_protocol(url)

        headers, cookies, content = get_headers_cookies(
            url,headers = prepare_headers() ,verify_ssl=config['verify_ssl'], timeout=config['timeout']
        )
        tech_stack = get_tech_stack(headers=headers, cookies=cookies, content=content)
        if config.get("safe_mode") and SAFE_MODE_SETTINGS["limit_tech_stack"]:
            ssl_info = None  # Skip SSL
            print_info("[safe-mode] SSL/TLS info collection skipped.")
        else:
            ssl_info = get_ssl_info(url, timeout=config['timeout'])

        # Prepare output as text for CLI output
        output_lines = []
        output_lines.append("\n[+] Technology Stack:")
        for category, techs in tech_stack.items():
            output_lines.append(f"- {category}:")
            for tech in techs:
                output_lines.append(f"  • {tech}")

        if ssl_info:
            output_lines.append("\n[+] SSL/TLS Info:")
            for key, value in ssl_info.items():
                output_lines.append(f"- {key}: {value}")

        output_text = "\n".join(output_lines)
        print_success(output_text,log = config.get("log"))

        # Save results if configured
        if config['save_file']:
            hostname = urlparse(url).hostname or "output"
            # Combine tech_stack and ssl_info for saving
            data_to_save = {
                "tech_stack": tech_stack,
                "ssl_info": ssl_info
            }
            save_results(hostname, "techfingerprint", data_to_save)
    except Exception as e:
        print_error(f"Experienced error as: {e}",show_traceback=config.get('debug'))
        typer.Exit(code=1)

cve_data_loaded = False

def load_cve_data_once():
    global cve_data_loaded
    if not cve_data_loaded:
        init_cve_db('cves.db')
        files = list_files_in_folder('cves_jsons')
        for file in files:
            import_cves_from_json(file, "cves.db")
        cve_data_loaded = True

@app.command(help = "Scan the target's tech stack for known CVEs")
@safe_cli
def cvescan(url: str):
    """Scan the target's tech stack for known CVEs."""
    try:
        
        load_cve_data_once()  # Initialize CVE DB only here

        url = auto_fix_url_protocol(url)

        headers, cookies, content = get_headers_cookies(
            url,headers = prepare_headers(), verify_ssl=config['verify_ssl'], timeout=config['timeout']
        )
        try:
            if headers is None or cookies is None or content is None:
                raise ValueError("Failed to fetch headers, cookies, or content.")
        except ValueError as v:
            print_error(f"Experienced error as: {v}")
            raise typer.Exit(code=1)

        tech_stack = get_tech_stack(headers=headers, cookies=cookies, content=content)
        
        if config.get("safe_mode") and SAFE_MODE_SETTINGS["limit_tech_stack"]:
            ssl_info = None
            print_info("[safe-mode] SSL/TLS info collection skipped.")
        else:
            ssl_info = get_ssl_info(url, timeout=config['timeout'])

        flat_techs = [tech for techs in tech_stack.values() for tech in techs]

        results = scan_for_cves_local(flat_techs)

        # Prepare CLI output
        if results:
            output_lines = []
            output_lines.append("\n[+] CVE Results:")
            for tech, cves in results.items():
                output_lines.append(f"- {tech}:")
                for cve in cves:
                    output_lines.append(f"  • {cve['id']}: {cve['summary']}")

            if ssl_info:
                output_lines.append("\n[+] SSL/TLS Info:")
                for key, value in ssl_info.items():
                    output_lines.append(f"- {key}: {value}")

            output_text = "\n".join(output_lines)
            print_success(output_text,log = config.get("log"))

            # Save results if configured
            if config['save_file']:
                hostname = urlparse(url).hostname or "output"
                # Save the raw results dict (CVE results + ssl info)
                data_to_save = {
                    "cve_results": results,
                    "ssl_info": ssl_info
                }
                save_results(hostname, "cvescan", data_to_save)
        else: 
            print_info('[!] No CVEs found – this may be due to missing version data or unrecognized technologies.',
                       log = config.get("log"))
    except Exception as e:
        print_error(f"Experienced error as: {e}",show_traceback=config.get('debug'))
        typer.Exit(code=1)

NVD_1_1_FEEDS = [
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}{}.json.gz".format(year, suffix)
    for year in range(2002, datetime.now().year + 1)
    for suffix in ("", "-modified")
]
@app.command("update-cves",help="Updates the cves.db with latest cves")
@safe_cli
def update_cve_data():
    """
    Download and overwrite all latest NVD 1.1 CVE JSON feeds, then import into the local DB.
    """
    cve_folder = "cves_jsons"
    os.makedirs(cve_folder, exist_ok=True)
    
    print_info(" Downloading and replacing existing CVE JSON files...")
    failed_urls = []

    for url in NVD_1_1_FEEDS:
        filename = url.split("/")[-1].replace(".gz", "")
        gz_path = os.path.join(cve_folder, filename + ".gz")
        json_path = os.path.join(cve_folder, filename)

        try:
            resp = fetch_with_retry(url, timeout=30)
            if resp.status_code == 200:
                with open(gz_path, "wb") as f:
                    f.write(resp.content)

                import gzip, shutil
                with gzip.open(gz_path, "rb") as f_in, open(json_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

                os.remove(gz_path)
                print_success(f" Updated {filename}")
            else:
                print_info(f" Skipped {filename}: HTTP {resp.status_code}")
                failed_urls.append(url)
        except Exception as e:
            print_error(f"Failed to fetch {url}: {e}", show_traceback=config.get("debug"))
            failed_urls.append(url)

    if failed_urls:
        print_error(f"Failed to update {len(failed_urls)} feed(s). See logs.")
        raise typer.Exit(code=1)

    print_info(" Importing updated CVEs into the database...")
    files = list_files_in_folder(cve_folder)
    for file in files:
        try:
            import_cves_from_json(file, "cves.db")
            print_success(f" Imported {file}")
        except Exception as e:
            print_error(f"Failed to import {file}: {e}", show_traceback=config.get("debug"))

    print_success(" CVE database update complete.")


if __name__ == "__main__":
    app()

