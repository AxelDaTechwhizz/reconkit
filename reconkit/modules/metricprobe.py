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

# Updated TECH_PATH_HINTS with more frameworks
TECH_PATH_HINTS = {
    "Go": ["/debug/vars", "/debug/pprof"],
    "Spring Boot": ["/actuator/metrics", "/actuator/health", "/actuator/prometheus"],
    "Node.js": ["/metrics", "/status", "/health"],
    "Prometheus": ["/metrics", "/federate"],
    "Grafana": ["/grafana/", "/api/metrics", "/api/health"],
    "Express": ["/health", "/metrics", "/status"],
    "Flask": ["/metrics", "/healthz"],
    "Django": ["/metrics", "/healthcheck"],
    "Kubernetes": ["/metrics", "/healthz"]
}

# Additional keywords for metric detection
KEYWORDS = [
    r'#\s*HELP', r'"uptime"', r'"heap"', r'"gc"', r'process_', r'jvm_', 
    r'nodejs_', r'go_gc_', r'spring_', r'"metrics"', r'http_requests_total',
    r'python_info', r'flask_', r'django_', r'kube_'
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
    text_lower = text.lower()
    if "# HELP" in text or any(x in text_lower for x in ['prometheus', 'process_']):
        return "Prometheus"
    if any(x in text_lower for x in ['jvm_', 'java_']):
        return "JVM"
    if any(x in text_lower for x in ['spring_', 'actuator']):
        return "Spring"
    if any(x in text_lower for x in ['go_', 'golang']):
        return "Go"
    if any(x in text_lower for x in ['node_', 'nodejs_']):
        return "Node.js"
    if any(x in text_lower for x in ['python_', 'flask_', 'django_']):
        return "Python"
    if any(x in text_lower for x in ['kube_', 'kubernetes_']):
        return "Kubernetes"
    return "Unknown"

def probe_single_url(base_url: str, path: str, headers: dict, timeout: int,
                    throttle: float, verify_ssl: bool, allow_redirects: bool) -> Optional[Dict[str, Any]]:
    full_url = urljoin(base_url, path.lstrip('/'))
    try:
        r = fetch_with_retry(full_url, headers=headers, timeout=timeout,
                            throttle=throttle, verify_ssl=verify_ssl,
                            allow_redirects=allow_redirects)

        content_type = r.headers.get('Content-Type', '')
        body = r.text[:2000]  # Increased preview size
        
        # Enhanced detection logic
        is_metric_endpoint = (
            'metrics' in path.lower() or 
            'actuator' in path.lower() or
            match_metrics_keywords(body)
        )
        
        if r.status_code in [200, 401, 403] and is_metric_endpoint:
            return {
                'url': full_url,
                'status': r.status_code,
                'content_type': content_type,
                'preview': body.strip()[:300],  # Larger preview
                'metric_type': guess_metric_type(body),
                'tech_hint': path  # Include which path led to discovery
            }
    except Exception as e:
        print_warning(f"Error probing {full_url}: {str(e)[:100]}")  # Truncate long errors
    return None

def scan_target(target: str, max_threads: int, headers: dict, throttle: float,
               timeout: int = 5, verify_ssl: bool = True, allow_redirects: bool = True) -> Optional[List[Dict[str, Any]]]:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    
    console.rule(f"[bold green]Metric Probe: {target}", style="green")
    
    try:
        response = fetch_with_retry(target, throttle=throttle, headers=headers,
                                  timeout=timeout, verify_ssl=verify_ssl,
                                  allow_redirects=allow_redirects)
    except Exception as e:
        print_error(f"Failed to fetch {target}: {str(e)[:200]}")
        return None
    
    techs = get_tech_stack(headers=response.headers, cookies=response.cookies, content=response.text)
    print_info(f"Detected tech stack: {', '.join(techs) if techs else 'None'}")
    
    wordlist = build_wordlist(techs)
    findings = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_path = {
            executor.submit(probe_single_url, target, path, headers, timeout,
                          throttle, verify_ssl, allow_redirects): path 
            for path in wordlist
        }
        
        for future in as_completed(future_to_path):
            result = future.result()
            if result:
                findings.append(result)
                # Immediate feedback for found endpoints
                console.print(
                    f"[green]✓[/green] [cyan]{result['url']}[/cyan] "
                    f"[white]{result['status']}[/white] "
                    f"[yellow]{result['metric_type']}[/yellow]"
                )

    if not findings:
        print_warning("No exposed metric endpoints found.")
        return None
    
    # Present final results in a table
    table = Table(title="Metric Endpoints Found", show_header=True, header_style="bold magenta")
    table.add_column("URL", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Type", style="yellow")
    table.add_column("Preview", style="dim")
    
    for finding in findings:
        table.add_row(
            finding['url'],
            str(finding['status']),
            finding['metric_type'],
            finding['preview']
        )
    
    console.print(table)
    return findings

def batch_metric_probe(targets: list, max_threads: int, headers: dict, throttle: float,
                      timeout: int = 5, verify_ssl: bool = True, allow_redirects: bool = True
                      ) -> List[Dict[str, Any]]:
    from rich.progress import track
    all_findings = []
    
    for target in track(targets, description="Scanning targets..."):
        findings = scan_target(
            target.strip(),
            max_threads=max_threads,
            headers=headers,
            throttle=throttle,
            timeout=timeout,
            verify_ssl=verify_ssl,
            allow_redirects=allow_redirects
        )
        if findings:
            all_findings.extend(findings)
    
    return all_findings

