import json, sys, sqlite3, datetime, time, hashlib, os
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm
from threading import local
from reconkit.modules.utils import print_success, save_to_file, print_warning

BATCH_SIZE = 1000
MAX_RETRIES = 5
_thread_local = local()

def get_connection(db_path: str = "cves.db") -> sqlite3.Connection:
    """Get or create a thread-local SQLite connection with concurrency settings."""
    if not hasattr(_thread_local, "conn"):
        conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        _thread_local.conn = conn
    return _thread_local.conn


def init_cve_db(db_path: str = "cves.db") -> None:
    """Initialize SQLite DB and create CVE table and indexes if not exist."""
    conn = get_connection(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            description TEXT,
            part TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            "update" TEXT,
            edition TEXT,
            language TEXT,
            published_date TEXT
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cpe ON cves(part, vendor, product, version)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_date ON cves(published_date)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS imports (
            filepath TEXT PRIMARY KEY,
            filehash TEXT,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def parse_cpe_uri(uri: str) -> Optional[Dict[str, str]]:
    """Parse CPE 2.3 URI string into components."""
    parts = uri.split(":")
    if len(parts) < 13:
        return None
    return {
        "part": parts[2].lower(),
        "vendor": parts[3].lower(),
        "product": parts[4].lower(),
        "version": parts[5],
        "update": parts[6],
        "edition": parts[7],
        "language": parts[8],
    }


def safe_batch_insert(conn, insert_values):
    for attempt in range(MAX_RETRIES):
        try:
            with conn:
                conn.executemany('''
                    INSERT OR IGNORE INTO cves
                    (id, description, part, vendor, product, version, "update", edition, language, published_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', insert_values)
            return True
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                time.sleep(0.1 * (attempt + 1))
            else:
                raise
    print(f"[!] Failed to insert batch after {MAX_RETRIES} retries due to DB lock.")
    return False


def import_cves_from_json(json_path: str, db_path: str = "cves.db", show_traceback: bool = True) -> str:
    """Import CVEs from JSON file into local SQLite database with batching and file hash check."""

    def file_hash(path: str) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    try:
        current_hash = file_hash(json_path)

        conn = get_connection(db_path)
        c = conn.cursor()

        # Safety: check schema columns
        c.execute("PRAGMA table_info(cves)")
        columns = {row[1] for row in c.fetchall()}
        required = {"id", "description", "part", "vendor", "product", "version", "update", "edition", "language", "published_date"}
        if not required.issubset(columns):
            print_warning("[!] Schema mismatch in 'cves' table. Recreating database...")
            conn.close()
            os.remove(db_path)
            init_cve_db(db_path)
            conn = get_connection(db_path)
            c = conn.cursor()
            print_success("CVE DB schema reset successfully.", log = True)



        # Check if file already imported
        c.execute('SELECT filehash FROM imports WHERE filepath = ?', (json_path,))
        row = c.fetchone()
        if row and row[0] == current_hash:
            return f"File '{json_path}' already imported with matching hash. Skipping."

        # Load JSON
        with open(json_path, 'r', errors='ignore') as file:
            data = json.load(file)

        items = data.get("CVE_Items", [])
        if not items:
            return f"No CVE items found in '{json_path}'."

        insert_values: List[Tuple] = []
        count = 0
        use_tqdm = sys.stdout.isatty()
        iterator = tqdm(items, desc=f"Importing {json_path}") if use_tqdm else items

        for item in iterator:
            cve_id = item['cve']['CVE_data_meta']['ID']
            desc_data = item['cve']['description'].get('description_data', [])
            desc = " ".join(d['value'] for d in desc_data if d.get("lang") == "en") or "No description available."
            pub_date = item.get("publishedDate", "")

            configs = item.get("configurations", {}).get("nodes", [])
            for node in configs:
                cpe_matches = node.get("cpe_match", [])
                if not cpe_matches and node.get("children"):
                    for child_node in node["children"]:
                        cpe_matches.extend(child_node.get("cpe_match", []))

                for cpe in cpe_matches:
                    uri = cpe.get("cpe23Uri", "")
                    parsed = parse_cpe_uri(uri)
                    if not parsed or parsed["version"] in ["*", "-", ""]:
                        continue
                    insert_values.append((
                        cve_id,
                        desc,
                        parsed["part"],
                        parsed["vendor"],
                        parsed["product"],
                        parsed["version"],
                        parsed["update"],
                        parsed["edition"],
                        parsed["language"],
                        pub_date
                    ))
                    count += 1

                    if count % BATCH_SIZE == 0:
                        if not safe_batch_insert(conn, insert_values):
                            return f"Database insert failed repeatedly. Aborting import for '{json_path}'."
                        insert_values.clear()

        if insert_values:
            if not safe_batch_insert(conn, insert_values):
                return f"Final insert failed for '{json_path}'."

        # Record import
        c.execute('''
            INSERT INTO imports (filepath, filehash, imported_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(filepath) DO UPDATE SET filehash=excluded.filehash, imported_at=CURRENT_TIMESTAMP
        ''', (json_path, current_hash))
        conn.commit()
        return f"Successfully imported {count} CVEs from '{json_path}'."

    except Exception as e:
        import traceback
        if show_traceback:
            traceback.print_exc()
        return f"Error importing '{json_path}': {e}"


def lookup_local_cves(product: str, version: str, db_path: str = "cves.db") -> List[Dict[str, str]]:
    """Query the local CVE DB for CVEs matching product and version."""
    product = product.lower()
    version = version.lower()

    results_set = set()
    results_list = []

    conn = get_connection(db_path)
    c = conn.cursor()

    query_exact = """
        SELECT id, description FROM cves 
        WHERE product = ?
          AND (version = ? OR version = '*' OR version = '-')
    """
    c.execute(query_exact, (product, version))
    for cve_id, desc in c.fetchall():
        if cve_id not in results_set:
            results_set.add(cve_id)
            results_list.append({"id": cve_id, "description": desc})

    query_prefix = """
        SELECT id, description FROM cves 
        WHERE product = ?
          AND version LIKE ?
    """
    c.execute(query_prefix, (product, version + '.%'))
    for cve_id, desc in c.fetchall():
        if cve_id not in results_set:
            results_set.add(cve_id)
            results_list.append({"id": cve_id, "description": desc})

    return results_list


def scan_for_cves_local(
    detected_techs: list[str],
    filename: Optional[str] = None,
    save_to_file: bool = False,
    db_path: str = "cves.db"
) -> Dict[str, List[Dict[str, str]]]:
    """Scan detected tech stack against local CVE database."""
    found = {}

    for i in range(0, len(detected_techs), 2):
        tech = detected_techs[i]
        version = detected_techs[i + 1] if i + 1 < len(detected_techs) else None
        if not version:
            continue
        results = lookup_local_cves(tech, version, db_path=db_path)
        if results:
            found[f"{tech}_{version}"] = results

    if save_to_file and filename:
        save_to_file(filename, found)

    return found
