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
git clone https://github.com/yourusername/ReconKit.git
cd ReconKit
pip install -r requirements.txt

## to install globally:

pip install . 

## After first install run:

reconkit update-cves


## Usage

python reconkit.py --target example.com [OPTIONS]

python reconkit.py --target example.com --subdomains --fingerprint --cves

## Available flags

--subdomains Run subdomain enumeration

--dirs     Run directory brute-forcing

--fingerprint Run tech fingerprinting

--cves     Match CVEs based on detected tech

--debug    Enable traceback output

--output results.json Save results to file

