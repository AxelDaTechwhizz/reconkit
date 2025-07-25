# ReconKit

**ReconKit** is a powerful, modular reconnaissance tool for web application and infrastructure analysis. Designed for bug bounty hunters, security researchers, and penetration testers, ReconKit automates and streamlines information gathering with a sharp focus on performance, extensibility, and usability.

---

## 🚀 Features

- 🌐 **Subdomain Enumeration**  
  Discover subdomains using multiple data sources and custom wordlists.

- 🔍 **Directory Brute Forcing**  
  Identify hidden endpoints and directories with configurable HTTP scanning.

- 🧠 **Technology Fingerprinting**  
  Detect web technologies via HTTP headers, cookies, and content-based signatures.

- ⚠️ **CVE Scanner**  
  Match detected technologies with local CVE datasets for quick vulnerability insights.

- 🛠️ **Modular Design**  
  Add new recon modules easily and toggle features via CLI flags.

- 🐛 **Debugging Mode**  
  Enable detailed traceback with `--debug` for troubleshooting.

---

## 📦 Installation

```bash
git clone https://github.com/AxelDaTechwhizz/reconkit.git
cd reconkit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

## After first install run:

reconkit update-cves


# Example usage:

python reconkit.py [flags] subenum --domain example.com
python reconkit.py [flags] dirscan --url https://example.com

## Available flags

--subdomains Run subdomain enumeration

--dirs     Run directory brute-forcing

--fingerprint Run tech fingerprinting

--cves     Match CVEs based on detected tech

--debug    Enable traceback output

--output results.json Save results to file

