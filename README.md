# cybersecurity-portfolio
Basic Antivirus Simulation

# Cybersecurity Portfolio

Academic and internship security projects built in Python and tested on legal targets.

---

## Projects

### 1. Network Port Scanner
Scans a target host for open ports and grabs service banners.
- **Tools used:** Python, socket, concurrent.futures
- **Tested on:** localhost, lab VMs

**Run it:**
```bash
python scanner.py 127.0.0.1 --start 1 --end 1024
```

---

### 2. Web Vulnerability Tester
Tests web applications for SQL Injection and XSS vulnerabilities.
- **Tools used:** Python, requests, BeautifulSoup
- **Tested on:** http://testphp.vulnweb.com/ (legal intentionally vulnerable target)

**Run it:**
```bash
python tester.py http://testphp.vulnweb.com/
```

---

### 3. Packet Analyzer
Captures and analyzes live network packets. Detects suspicious patterns.
- **Tools used:** Python, Scapy
- **Tested on:** Local network interface only

**Run it:**
```bash
sudo python analyzer.py -i eth0 -c 100
```

---

### 4. Antivirus Simulator
Signature-based file scanner with quarantine and real-time monitoring.
- **Tools used:** Python, hashlib, watchdog
- **Tested on:** Custom test files with known hashes

**Run it:**
```bash
python av_sim.py scan ./test_folder --quarantine --report report.json
```

---

## Installation

```bash
git clone https://github.com/yourusername/security-projects
cd security-projects
pip install -r requirements.txt
```

## Requirements
