import re
import sys
import os
import reconkit.modules.utils
from tqdm import tqdm
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from json import loads as json_loads
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Optional




def subdomain_finder(domain: str, max_workers: int,
                     headers : dict,throttle : float,
                     save_file: bool = False, file_format: str = 'txt',
                     recursive: bool = False, max_depth: int = 1,
                     _depth: int = 0, _visited: Optional[Set[str]] = None) -> Dict:
    """
    Finds subdomains for a given domain using multiple sources.
    :param domain: Domain to find subdomains for
    :param max_workers: Maximum number of threads to use for fetching subdomains
    :param save_file: Whether to save the results to a file
    :param file_format: Format to save the results ('txt', 'json', 'csv')
    :return: Dictionary with domain and its subdomains
    """
    
    if not domain:
        raise ValueError("Domain cannot be empty")
    
    if not reconkit.modules.utils.is_valid_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    if _visited is None:
        _visited = set()
    
    _visited.add(domain)

    text_sources = {'dnsdumpster', 'rapiddns', 'webarchive_robots'}
    raw_json_sources = {'crtsh', 'omnisint', 'jldc', 'gau'}

    sources = {
        'hackertarget': f"https://api.hackertarget.com/hostsearch/?q={domain}",
        'crtsh': f"https://crt.sh/?q=%25.{domain}&output=json",
        'bufferover': f"https://dns.bufferover.run/dns?q={domain}",
        'threatcrowd': f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
        'alienvault': f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        'sublist3r': f"https://api.sublist3r.com/search.php?domain={domain}",
        'webarchive_cdx': f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey",
        'threatminer': f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
        'webarchive_robots': f"http://web.archive.org/web/*/http://{domain}/robots.txt",
        'dnsdumpster': f"https://dnsdumpster.com/lookup/{domain}",
        'rapiddns': f"https://rapiddns.io/subdomain/{domain}?full=1",
        'omnisint': f"https://sonar.omnisint.io/subdomains/{domain}",
        'jldc': f"https://jldc.me/anubis/subdomains/{domain}",
        'gau': f"https://api.allorigins.win/raw?url=https://gau.io/subdomains/{domain}"
    }

    def parse_html_list(text: str, pattern: str) -> Set[str]:
        return set(re.findall(pattern, text))

    parsers = {
        'hackertarget': lambda t: set(line.split(',')[0] for line in t.splitlines() if ',' in line),
        'crtsh': lambda d: set(e['name_value'].lower() for e in d if 'name_value' in e),
        'bufferover': lambda d: set(l.split(',')[1] for l in d.get('FDNS_A', []) if ',' in l),
        'threatcrowd': lambda d: set(d.get('subdomains', [])),
        'alienvault': lambda d: set(e['hostname'] for e in d.get('passive_dns', [])),
        'sublist3r': lambda d: set(d),
        'webarchive_cdx': lambda d: {u.split('/')[2] for u, *_ in d[1:] if domain in u},
        'threatminer': lambda d: set(d.get('results', [])),
        'webarchive_robots': lambda t: set(re.findall(rf'https?://([\w\.-]*\.{re.escape(domain)})', t)),
        'dnsdumpster': lambda t: parse_html_list(t, rf'[\w\.-]+\.{re.escape(domain)}'),
        'rapiddns': lambda t: parse_html_list(t, rf'[\w\.-]+\.{re.escape(domain)}'),
        'omnisint': lambda t: set(json_loads(t)),
        'jldc': lambda t: set(json_loads(t)),
        'gau': lambda t: set(json_loads(t))
    }

    results = set()
    failures = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(reconkit.modules.utils.fetch_with_retry,headers, url): src for src, url in sources.items()}
        futures_iter = tqdm(as_completed(futures), total=len(futures), desc=f"Scanning {domain}", unit="src") \
    if sys.stdout.isatty() else as_completed(futures)
        
        for future in futures_iter:
    
            src = futures[future]
            reconkit.modules.utils.print_info(f"Fetching {src}…")
            
            try:
                resp = future.result()

                if not resp or not resp.ok:
                    raise Exception(f"Failed to fetch {src}: {resp.status_code if resp else 'No Response'}")
                
                if src in text_sources:
                    try:
                        data = resp.text
                    except Exception as e:
                        raise Exception(f"Failed to fetch text from {src}") from e
                elif src in raw_json_sources:
                    try:
                        data = json_loads(resp.text)
                    except ValueError as ve:
                        raise Exception(f"Failed to parse JSON from {src}") from ve
                else:
                    try:
                        data = resp.json()
                    except ValueError as ve:
                        raise Exception(f"Failed to parse JSON from {src}") from ve

                subs = parsers[src](data)
                norm = {s.lower().rstrip('.') for s in subs if s and s.endswith(domain)}
                if norm:
                    reconkit.modules.utils.print_success(f"{len(norm)} subs from {src}")
                    results.update(norm)
                else:
                    reconkit.modules.utils.print_info(f"No subs from {src}")
                
            except Exception as e:
                failures[src] = str(e)
                reconkit.modules.utils.print_error(f"{src} error: {e}")
                
                
    



    recursive_results = set()

    # --- 🔁 Recursive Enumeration ---
    if recursive and _depth < max_depth:
        child_domains = {sub for sub in results if sub not in _visited and sub.endswith(domain)}
        desc = f"Depth {_depth + 1} of {max_depth}" if recursive else f"Scanning {domain}"
        child_iter = tqdm(child_domains, desc=desc, unit="subdomain") \
    if sys.stdout.isatty() else child_domains

        for child in child_iter:

            try:
                child_result = subdomain_finder(
                    domain = child,
                    headers = headers,
                    max_workers = max_workers,
                    save_file = False,
                    file_format = file_format,
                    recursive = recursive,
                    max_depth = max_depth,
                    _depth =_depth + 1,
                    _visited =_visited
                )
                
                recursive_results.update(child_result.get('subdomains', []))
            except Exception as e:
                reconkit.modules.utils.print_error(f"Recursive error on {child}: {e}")
                failures[child] = str(e)

    final_results = results.union(recursive_results)

    if save_file and _depth == 0:  # Save only at top level call
            filename = f"{domain}_subdomains.{file_format}"
            reconkit.modules.utils.save_to_file(filename, sorted(final_results))

    return {
        'domain': domain,
        'subdomains': sorted(final_results),
        'failures': failures if failures else None
    }


def subdomain_from_file(filename: str, max_workers: int, save_file: bool,
                        headers : dict, rmin_throttle : float,recursive: bool , max_depth: int,
                        rmax_throttle : float,file_format: str = 'txt') -> Dict[str, List[str]]:
    """
    Reads a file containing domains and finds subdomains for each domain using multiple sources.
    :param filename: Path to the input file containing domains
    :param max_workers: Maximum number of threads to use for fetching subdomains
    :param save_file: Whether to save the results to a file
    :param file_format: Format to save the results ('txt', 'json', 'csv')
    :return: Dictionary with domains as keys and lists of subdomains as values
    """
    try:
        reconkit.modules.utils.validate_input_file(filename)
    except Exception as e:
        reconkit.modules.utils.print_error(f"An error occurred: {e}") 
        return {}

    results = {}

    with open(filename, 'r', encoding='utf-8') as file:
        domains = [line.strip() for line in file if line.strip()]
        if not domains:
            raise ValueError("No valid domains found in the file")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(subdomain_finder,domain, max_workers,headers, save_file,
                             file_format,recursive, max_depth): domain
            for domain in domains
        }

        future_iter = tqdm(as_completed(futures), total=len(futures), desc="Enumerating domains", unit="domain") \
    if sys.stdout.isatty() else as_completed(futures)

        for future in future_iter:

            domain = futures[future]
            try:
                result = future.result()
                if isinstance(result, dict):
                    results[domain] = result.get('subdomains', [])
                else:
                    reconkit.modules.utils.print_error(f"Unexpected result type for {domain}")
                reconkit.modules.utils.random_throttle(rmin_throttle, rmax_throttle)
            except Exception as e:
                reconkit.modules.utils.print_error(f"Error processing domain {domain}: {e}")
                reconkit.modules.utils.log_to_file(f"Error processing domain {domain}: {e}", 'error')

    if save_file:
        base = os.path.basename(os.path.splitext(filename)[0])
        filename = f"results_{base.lower()}.{file_format.lstrip('.')}"
        reconkit.modules.utils.save_to_file(filename, results)

    return results


"""
Function to generate a custom subdomain wordlist based on a domain
This function will create a wordlist based on the domain name, which can be used for subdomain enumeration.
"""


def generate_custom_wordlist(domain: str,
                              wordlist_path: Optional[str] = None,
                              headers : dict = None,save_file: bool = False,
                              filename: Optional[str] = None,
                              file_format:str='txt') -> Set[str]:
    """
    Generates a custom subdomain wordlist based on scraping a target domain and optional wordlist file.

    :param domain: Target domain (e.g., example.com)
    :param wordlist_path: Path to wordlist file (one word per line)
    :param save_file: Save result to file
    :param filename: Optional output filename
    :return: Set of discovered subdomains
    """
    if not reconkit.modules.utils.is_valid_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")

    base_url = f"https://{domain}"
    subdomains = set()

    def extract_subdomains(text: str) -> Set[str]:
        pattern = rf"\b((?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)})\b"
        found = set(re.findall(pattern, text, re.IGNORECASE))
        return {s.lower().strip('.') for s in found if s.lower() != domain}

    def fetch_content(url: str) -> str:
        response = reconkit.modules.utils.fetch_url(url,headers=headers)
        if response and response.ok:
            return response.text
        return ""

    # 1. Main page
    html = fetch_content(base_url)
    subdomains.update(extract_subdomains(html))

    # 2. robots.txt
    robots_txt = fetch_content(urljoin(base_url, "/robots.txt"))
    subdomains.update(extract_subdomains(robots_txt))

    # 3. sitemap.xml
    sitemap_xml = fetch_content(urljoin(base_url, "/sitemap.xml"))
    subdomains.update(extract_subdomains(sitemap_xml))

    # 4. JS files
    soup = BeautifulSoup(html, 'html.parser')
    script_tags = soup.find_all('script', src=True)
    js_urls = {
        urljoin(base_url, tag['src'])
        for tag in script_tags if tag['src'].endswith('.js')
    }

    for js_url in js_urls:
        js_code = fetch_content(js_url)
        subdomains.update(extract_subdomains(js_code))

    # 5. Load words from file and build subdomains
    if wordlist_path:
        try:
            reconkit.modules.utils.validate_input_file(wordlist_path)
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    word = line.strip().lower()
                    if word:
                        subdomains.add(f"{word}.{domain}")
        except Exception as e:
            reconkit.modules.utils.print_error(f"Failed to load wordlist from {wordlist_path}: {e}")

    # 6. Save results
    try:
        if save_file:
            if not filename:
                filename = f"{domain}_custom_wordlist.{file_format}"
            reconkit.modules.utils.save_to_file(filename, sorted(subdomains))
    except Exception as e:
        reconkit.modules.utils.print_error(f"An error occured as: {e}")  

    return subdomains


    