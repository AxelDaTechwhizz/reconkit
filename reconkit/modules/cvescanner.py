import reconkit.modules.utils
import json
import sqlite3
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm
import sys


BATCH_SIZE = 1000

def init_cve_db(db_path: str = "cves.db") -> None:
    """Initialize SQLite DB and create CVE table and indexes if not exist."""
    with sqlite3.connect(db_path) as conn:
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

import hashlib

def import_cves_from_json(json_path: str, db_path: str = "cves.db", show_traceback: bool = True) -> None:
    """Import CVEs from JSON file into local SQLite database with batching and file hash check."""
    def file_hash(path: str) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    try:
        # Compute current file hash
        current_hash = file_hash(json_path)

        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            # Create table to track imported files and their hashes if not exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS imports (
                    filepath TEXT PRIMARY KEY,
                    filehash TEXT,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Check if this file hash was already imported
            c.execute('SELECT filehash FROM imports WHERE filepath = ?', (json_path,))
            row = c.fetchone()
            if row and row[0] == current_hash:
                print(f"File '{json_path}' already imported with matching hash. Skipping import.")
                return  # Skip import

        # Proceed with original import logic
        with open(json_path, 'r', errors='ignore') as file:
            data = json.load(file)
            reconkit.modules.utils.print_success(f"Total CVE items in file: {len(data.get('CVE_Items', []))}")

    except Exception as e:
        reconkit.modules.utils.print_error(f"Error loading JSON: {e}", show_traceback=show_traceback)
        return

    try:
        count = 0
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            insert_values: List[Tuple] = []
            

            items = data.get("CVE_Items", [])
            use_tqdm = sys.stdout.isatty()

            iterator = tqdm(items, desc="Importing CVEs") if use_tqdm else items

            for item in iterator:

                cve_id = item['cve']['CVE_data_meta']['ID']

                desc_data = item['cve']['description'].get('description_data', [])
                desc = " ".join(
                    d['value'] for d in desc_data if d.get("lang") == "en"
                ) or "No description available."

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
                        if not parsed:
                            continue
                        if parsed["version"] in ["*", "-", ""]:
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
                            c.executemany('''
                                INSERT OR IGNORE INTO cves
                                (id, description, part, vendor, product, version, "update", edition, language, published_date)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', insert_values)
                            conn.commit()
                            insert_values.clear()
                            # print(f"Imported {count} CVE entries so far...")

            if insert_values:
                c.executemany('''
                    INSERT OR IGNORE INTO cves
                    (id, description, part, vendor, product, version, "update", edition, language, published_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', insert_values)
                conn.commit()

            # Update or insert the file hash after successful import
            c.execute('''
                INSERT INTO imports (filepath, filehash, imported_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(filepath) DO UPDATE SET filehash=excluded.filehash, imported_at=CURRENT_TIMESTAMP
            ''', (json_path, current_hash))

    except Exception as e:
        reconkit.modules.utils.print_error(f"Error writing to DB: {e}")

    reconkit.modules.utils.print_success(f"Finished importing {count} CVE entries.")


def lookup_local_cves(
    product: str, 
    version: str, 
    db_path: str = "cves.db"
) -> List[Dict[str, str]]:
    """
    Query the local CVE DB for CVEs matching product and version.
    Supports exact, wildcard ('*', '-') and prefix version matches.
    """
    product = product.lower()
    version = version.lower()

    results_set = set()
    results_list = []

    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()

        # Exact version match or wildcard version entries
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

        # Prefix version match (e.g., 1.2 matches 1.2.3)
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
        reconkit.modules.utils.save_to_file(filename, found)

    return found
