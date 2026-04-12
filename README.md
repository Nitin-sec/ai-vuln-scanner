# ThreatMap Infra

> Automated VAPT Scanner & External Attack Surface Mapping Tool

---

##  Overview

ThreatMap Infra is a security-focused tool designed to automate **Vulnerability Assessment and Penetration Testing (VAPT)** workflows.

It performs reconnaissance, service discovery, vulnerability identification, and generates structured security reports — enabling faster and more consistent security assessments.

---

##  Key Features

*  Automated target discovery & enumeration
*  Network scanning and service identification
*  Vulnerability detection using multiple techniques
*  Structured report generation (VAPT-style)
*  Intelligent triage and contextual insights
*  Local processing (no external data dependency)
*  Designed for authorized security testing only

---

## How It Works

ThreatMap Infra follows a modular pipeline:

Discovery → Scanning → Analysis → Triage → Reporting

Each stage is designed to simulate real-world assessment workflows used in professional security engagements.

---

## Output

The tool generates structured reports including:

* Executive summary
* Risk distribution
* Key findings
* Detailed vulnerability analysis
* Remediation recommendations

Reports are designed to be **printable and client-ready**.

---

## Tech Stack

* Python
* Security tools integration (Nmap, Nikto, etc.)
* Local processing engine
* Structured reporting system

---

##  Installation

```bash
git clone https://github.com/Nitin-sec/ThreatMap-Infra.git
cd ThreatMap-Infra

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## ▶ Usage

```bash
./run.sh
```

Follow the prompts to provide a target and output location.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**.

Unauthorized scanning of systems is illegal and strictly prohibited.
The author is not responsible for misuse of this tool.

---

## 📜 License

This project is licensed under the MIT License.
