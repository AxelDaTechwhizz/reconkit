import re
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from reconkit.modules.techfingerprint import get_tech_stack
from reconkit.modules.utils import (
    print_info, print_success, print_warning, print_error,
    fetch_with_retry, save_to_file
)

COMMON_METRIC_PATHS = [
    "/metrics", "/status", "/health", "/debug/vars", "/actuator/metrics",
    "/stats", "/metrics/prometheus", "/monitoring", "/_stats", "/admin/metrics"
]

TECH_PATH_HINTS = {
    "Go": ["/debug/vars"],
    "Spring Boot": ["/actuator/metrics", "/actuator/health"],
    "Node.js": ["/metrics", "/status"],
    "Prometheus": ["/metrics"],
    "Grafana": ["/grafana/", "/api/metrics"],
    "Express": ["/health", "/metrics"]
}

KEYWORDS = [
    r'#\s*HELP', r'"uptime"', r'"heap"', r'"gc"', r'process_', r'jvm_', r'nodejs_',
    r'go_gc_', r'spring_', r'"metrics"'
]


def build_wordlist(techs=None):
    paths = set(COMMON_METRIC_PATHS)
    if techs:
        for tech in techs:
            paths.update(TECH_PATH_HINTS.get(tech, []))
    return sorted(paths)

def match_metrics_keywords(text):
    return any(re.search(kw, text, re.IGNORECASE) for kw in KEYWORDS)

def guess_metric_type(text):
    if "# HELP" in text or "nodejs_" in text or "go_gc_" in text:
        return "Prometheus"
    if "jvm_" in text:
        return "JVM"
    if "spring_" in text:
        return "Spring"
    return "Unknown"

def probe_single_url(base_url : str, path : str,headers : dict,timeout : int,
                     throttle : float,verify_ssl : bool,allow_redirects : bool) -> Optional[Dict[str, Any]]:
    full_url = urljoin(base_url, path.lstrip('/'))
    try:
        r = fetch_with_retry(full_url, headers=headers, timeout=timeout,throttle=throttle,
                             verify_ssl=verify_ssl, allow_redirects=allow_redirects)

        content_type = r.headers.get('Content-Type', '')
        body = r.text[:1000]
        if r.status_code in [200, 401, 403] and ('metrics' in path or match_metrics_keywords(body)):
            return {
                'url': full_url,
                'status': r.status_code,
                'content_type': content_type,
                'preview': body.strip()[:200],
                'metric_type': guess_metric_type(body)
            }
    except Exception as e:
        print_warning(f"Error probing {full_url}: {e}")

    return None

def scan_target(target : str, max_threads : int,headers: dict,throttle: float,
                timeout: int = 5, verify_ssl: bool = True,allow_redirects : bool = True) -> Optional[List[Dict[str, Any]]]:
    """
    Scans a target URL for exposed metric/debug endpoints.
    Returns a list of findings with URL, status code, content type, preview, and metric type.
    """
    from rich.console import Console
    console = Console()
    console.rule(f"[bold green]Metric Probe: {target}")

    try:
        response = fetch_with_retry(target,throttle=throttle, headers=headers, 
                                    timeout=timeout, verify_ssl=verify_ssl,allow_redirects=allow_redirects)
    except Exception as e:
        print_error(f"Failed to fetch {target}: {e}")
        return None
    
    techs = get_tech_stack(headers=response.headers,cookies=response.cookies,content=response.text)
    print_info(f"Detected tech stack: {', '.join(techs) if techs else 'None'}")
    wordlist = build_wordlist(techs)
    findings = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_path = {
            executor.submit(probe_single_url, target, path,headers ,timeout,
                     throttle ,verify_ssl ,allow_redirects ): path for path in wordlist
        }
        for future in as_completed(future_to_path):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        print_warning("No exposed metric endpoints found.")
        return None
    else:
        for r in findings:
            console.print(f"[cyan]{r['url']}[/cyan] [white]{r['status']}[/white] "
                          f"({r['content_type']}) - [bold]{r['metric_type']}[/bold]")
            console.print(f"[dim]{r['preview']}[/dim]\n")

    return findings

def batch_metric_probe(targets: list, max_threads: int, headers: dict,throttle: float,
                timeout: int = 5, verify_ssl: bool = True,allow_redirects : bool = True
                ) -> List[Dict[str, Any]]:
    
    all_findings = []

    for target in targets:
        findings = scan_target(target.strip(), max_threads=max_threads, 
                               headers=headers, throttle=throttle, timeout=timeout,
                               verify_ssl=verify_ssl, allow_redirects=allow_redirects)
        if findings:
            all_findings.extend(findings)

    
    return all_findings

