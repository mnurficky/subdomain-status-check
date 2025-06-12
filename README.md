# 🛡️ Subdomain Status Checker
A powerful Python script to check the status of subdomains by performing:
- DNS resolution
- Web server availability (HTTP/HTTPS)
- WHOIS-based IP ownership identification
- Hosting type detection (CDN, Cloud, VPS, Dedicated)
- Supports multi-threading for high-speed scanning and outputs results in .txt, .csv, and .json formats.
---
## 📦 Features
- 🌐 DNS Check: Verify if subdomain resolves to an IP
- 🔍 Web Status Check: Check if a web server is active (HTTP/HTTPS)
- 🧠 IP Owner Detection: WHOIS-based owner lookup
- ☁️ Hosting Type Heuristic: Detect if hosted on Cloud, CDN, VPS, etc.
- 📄 Export to `TXT`, `CSV`, `JSON`
- ⚡ Fast: Multi-threaded scanning
---
## 🚀 Installation & Usage
### 🔀 Clone the Repository
```bash
git clone https://github.com/mnurficky/subdomain-status-check.git
cd subdomain-status-checker
```
### 📦 Install Dependencies
```bash
pip install -r requirements.txt
```
### 🧪 Usage
Check a single subdomain:
```bash
python subdomain_check.py example.com
```
Check subdomains from a file `list.txt`:
```bash
python subdomain_check.py -d list.txt
```
Specify output file (automatically detects format from extension):
```bash
python subdomain_check.py -d list.txt -o result.csv
python subdomain_check.py -d list.txt -o result.json
python subdomain_check.py -d list.txt -o result
```
Control concurrency (default is 10 threads):
```bash
python subdomain_check.py -d list.txt -t 20
```
---
## 📤 Output Example
Each output line looks like this (also saved in file):
```bash
blog.example.com --> DNS: AKTIF (192.168.1.1) | WEB: HTTPS AKTIF (HTTP 200) | Owner: Cloudflare, Inc. | Hosting: CDN
```
## 📁 Example Subdomain File
```
www.example.com
api.example.com
blog.example.com
```
## ⚠️ Disclaimer
This tool is for educational and authorized testing only. Use it responsibly and do not scan domains you don't own or have permission to test.
