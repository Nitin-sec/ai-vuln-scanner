# threatmap

**Automated VAPT + EASM CLI Scanner with AI-assisted reporting**

ThreatMap is a terminal-first security tool that automates:

**Discovery → Scanning → Evidence → Reporting → Intelligence**

Built for:

* security engineers
* developers
* students
* bug bounty hunters

---

##  Why ThreatMap?

Most tools:

* give raw outputs
* require manual correlation
* are hard to interpret

**ThreatMap does it differently:**

*  Automated multi-tool orchestration (Nmap, Nuclei, etc.)
*  Clean reports (HTML, JSON, TXT, Excel)
*  Evidence-ready outputs for audits
*  Local AI (SLM) for explanations + remediation
*  Smooth CLI UX (no repeated commands)

---

##  Quick Start

```bash
git clone https://github.com/Nitin-sec/threatmap.git
cd threatmap

./install.sh
./threatmap
```

---

##  Usage Flow

```text
Start → Enter target → Confirm authorization → Scan → Reports → Menu
```

After scan:

```text
What would you like to do?

▶ Continue Scanning
  Open HTML Report
  Export Excel
  View Logs
  Exit
```

 No need to rerun the tool
 Continuous scanning session supported

---

##  Example Output

<img width="637" height="221" alt="image" src="https://github.com/user-attachments/assets/6d06332d-0e23-408f-a546-cd5fb3489eec" />
<img width="728" height="337" alt="image" src="https://github.com/user-attachments/assets/da22677a-5ca1-4131-b24a-8f65f631288e" />


###  Scan Progress

* Discovery
* Port Scanning
* Web Analysis
* Vulnerability Analysis

###  Reports

* HTML (human-friendly)
* Excel (client-ready)
* JSON (machine-readable)

---

##  Output Structure

```text
scans/<target_timestamp>/
├── raw/        → tool outputs
├── logs/       → execution logs
├── evidence/   → raw proof (nmap, nuclei, etc.)
├── report/     → final reports
```

---

##  AI (Local SLM)

ThreatMap uses **local models** for:

* vulnerability explanation
* remediation suggestions
* contextual insights

 No API keys
 No external data sharing
 Fully local

> If SLM is unavailable, ThreatMap falls back to structured analysis.

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**.

Allowed:

* your own systems
* client engagements
* bug bounty scope
* labs (HTB, THM, etc.)

Unauthorized scanning is illegal.

---

## 🛠️ Requirements

* Linux (Kali recommended)
* Python 3.10+
* Go tools (auto-installed)
* Optional: Minimum 4GB RAM for SLM

---

##  Tools Used

* Nmap
* Nuclei
* Subfinder
* Assetfinder
* Nikto
* WhatWeb

---

##  Contributing

Open to improvements, ideas, and collaboration.

---

##  If you like this project

Give it a star ⭐
It helps a lot.

---

##  Author

Built by Nitin-sec
Focused on cybersecurity + AI + automation
