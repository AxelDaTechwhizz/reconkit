from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import reconkit.modules.utils
import sys
import os

def http_dir_bruteforcer(word_list: str, url: str, timeout: int, throttle: float,
                         rmin_throttle: float, rmax_throttle: float, headers: dict = None,
                         save_to_file: bool = True, verify_ssl: bool = False, workers: int = 10,
                         file_format: str = '') -> dict:
    found_dirs = []

    url = reconkit.modules.utils.validate_url(url)
    if not url:
        return found_dirs

    if not reconkit.modules.utils.validate_input_file(word_list):
        reconkit.modules.utils.print_error(f"Invalid word list file: {word_list}")
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

    def check_directory(word):
        reconkit.modules.utils.throttle(throttle)
        base_url = url.rstrip('/') + '/'
        normalized_word = word.strip().strip('/')
        full_url = urljoin(base_url, normalized_word)
        response = reconkit.modules.utils.fetch_with_retry(full_url, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
        reconkit.modules.utils.random_throttle(rmin_throttle, rmax_throttle)

        if response and response.status_code in [200, 301, 302, 403]:
            reconkit.modules.utils.print_success(f"Found: {full_url} - Status: {response.status_code}")
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

    if save_to_file:
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
