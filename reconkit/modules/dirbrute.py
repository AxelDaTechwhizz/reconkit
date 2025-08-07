from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from time import sleep
from typing import List
import reconkit.modules.utils
from bs4 import BeautifulSoup
import sys
import os

def extract_path_prefixes_from_html(base_url: str,headers: dict,throttle: float,timeout: int, 
                                    verify_ssl: bool,allow_redirects: bool,log: bool,retries: int) -> List[str]:
    """Fetch and parse links from the target HTML to extract useful prefixes."""
    try:
        response = reconkit.modules.utils.fetch_with_retry(base_url, headers=headers,throttle=throttle,
                                                            timeout=timeout, verify_ssl=verify_ssl,
                                                            allow_redirects=allow_redirects,retries=retries)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        hrefs = [a.get('href') for a in soup.find_all('a', href=True)]
        prefixes = set()

        for href in hrefs:
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc != urlparse(base_url).netloc:
                continue  # skip external links

            path_parts = parsed.path.strip('/').split('/')
            if path_parts and len(path_parts) <= 2:
                # Only consider shallow paths to avoid noise
                first_segment = path_parts[0]
                if 0 < len(first_segment) < 30:
                    prefixes.add(first_segment + '/')

        return list(prefixes)

    except Exception as e:
        reconkit.modules.utils.print_warning(f"[smart-dirscan] Failed to extract HTML path prefixes: {e}",
                                             log = log)
        return []

def http_dir_bruteforcer(word_list: str, url: str, timeout: int, throttle: float,
                         rmin_throttle: float, rmax_throttle: float, headers: dict = None,
                         allow_redirecs: bool = True,save_to_file: bool = True, 
                         verify_ssl: bool = False, workers: int = 10,file_format: str = '',
                         filename: str = None) -> dict:
    
    found_dirs = []
    success_codes: List[int] = [200, 301, 302, 403]


    url = reconkit.modules.utils.validate_url(url)
    if not url:
        return found_dirs

    try:
        word_list = reconkit.modules.utils.validate_input_file(word_list)
    except Exception as e:
        reconkit.modules.utils.print_error(f"Recieved error as {e}")
        return found_dirs

    try:
        with open(os.path.abspath(word_list), 'r', encoding='utf-8') as file:
            words = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        reconkit.modules.utils.print_error(f"Word list file not found: {word_list}")
        return found_dirs
    except Exception as e:
        reconkit.modules.utils.print_error(f"An error occurred while reading word list: {str(e)}")
        return found_dirs

    if not words:
        reconkit.modules.utils.print_error("Word list is empty.")
        return found_dirs


    def check_directory(word):
        sleep(throttle)
        base_url = url.rstrip('/') + '/'
        normalized_word = word.strip().strip('/')
        full_url = urljoin(base_url, normalized_word)
        response = reconkit.modules.utils.fetch_with_retry(full_url,allow_redirects=allow_redirecs,
                                                           throttle=throttle, headers=headers, timeout=timeout, 
                                                           verify_ssl=verify_ssl)
        reconkit.modules.utils.random_throttle(rmin_throttle, rmax_throttle)

        if response and response.status_code in success_codes:
            return full_url
        else:
            reconkit.modules.utils.print_info(f"Checked: {full_url} - Status: {response.status_code if response else 'No Response'}")
            return None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_directory, word) for word in words]

        # tqdm with guard
        future_iter = tqdm(as_completed(futures), total=len(futures),
                           desc=f"Bruteforcing {url}", unit="dir") \
                           if sys.stdout.isatty() else as_completed(futures)

        for future in future_iter:
            try:
                result = future.result()
                if result:
                    found_dirs.append(result)
            except Exception as e:
                reconkit.modules.utils.print_error(f"Error in thread: {e}")

    tqdm.write(f"[+] {len(found_dirs)} directories found out of {len(words)} words.")

    if save_to_file:
        if not filename:
            netloc = urlparse(url).netloc.replace('.', '_').replace(':', '_')
            path = urlparse(url).path.strip('/').replace('/', '_') or 'root'
            filename = f"{netloc}__{path}_dirs.{file_format}"

        reconkit.modules.utils.save_to_file(filename=filename, data=found_dirs)

    return {
        "target": url,
        "found": found_dirs,
        "total_attempts": len(words),
        "success_count": len(found_dirs)
    }
