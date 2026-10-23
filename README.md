# WLAN Layer-2 Station Isolation Deficits & Asymmetric Evasion Thresholds

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23602802.svg)](https://doi.org/10.5281/zenodo.23602802)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1557.002-red.svg)](https://attack.mitre.org/techniques/T1557/002/)
[![IEEE Standard](https://img.shields.io/badge/IEEE-802.11w%20%2F%20RFC%20826-orange.svg)](https://standards.ieee.org/)
[![Status](https://img.shields.io/badge/Status-Research%20%2F%20Portfolio%20Ready-brightgreen.svg)]()

> **Author:** Arslan Wali (BS Computer Science)  
> **Academic Focus:** Applied Cybersecurity, Network Protocol Resilience, & Intrusion Detection Architectures  
> **Classification:** Empirical Cybersecurity Research / Reproducible Diagnostic Suite  

---

## 📌 Overview & Research Problem

Wireless Local Area Networks (WLANs) deployed in small-to-medium enterprise (SME) and Customer Premises Equipment (CPE) environments frequently operate under an unsegmented "flat" network architecture. While transport-layer encryption (TLS 1.3) has become standard, the data link layer (Layer 2) remains fundamentally dependent on the stateless, unauthenticated Address Resolution Protocol (RFC 826).

This repository contains the complete diagnostic software suite, experimental telemetry, and reproduction artifacts for the empirical research paper:  
📄 **[*An Empirical Study on Layer-2 Station Isolation Deficits and Asymmetric Evasion Thresholds in Wireless Broadcast Domains*](paper/research_paper.md)**.

### Core Research Questions
1. **RQ1:** *To what degree do commodity WLAN deployments enforce or default to Layer-2 Station Isolation in practice, and how does this affect lateral endpoint attack surfaces?*
2. **RQ2:** *What is the minimal frame injection frequency required to sustain near-100% ARP cache persistence on modern client operating systems, and does this rate evade default threshold-based intrusion detection rules?*

---

## 🔬 Key Empirical Findings

### 1. The Asymmetric Evasion Boundary ($H_1$)
Across five parameterized trials ($N = 3$ runs per condition, **2,400 discrete measurement checkpoints total**), we mapped the trade-off curve between injection interval ($\Delta t$), kernel cache persistence, and NIDS detection:

| Trial ID | Injection Interval ($\Delta t$) | Frequency ($f$) | Total Frames (per run) | Mean Cache Retention ($\pm \sigma$) | Suricata 7.0 Alert (Rate Threshold `sid:1000001`) | Zeek 6.0 (Default Sensor Profile) | Zeek 6.0 (Stateful `arp.zeek` Profile) | Evasion Verdict |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **T-1** | $0.2	ext{ s}$ | $5.0	ext{ Hz}$ | 1,600 | $100.0\% \pm 0.0\%$ | **TRIGGERED ($t = 1.2	ext{s}$)** | **SILENT (0 Alerts)** | **TRIGGERED ($t = 0.2	ext{s}$)** | Detected (Rate & State) |
| **T-2** | $0.5	ext{ s}$ | $2.0	ext{ Hz}$ | 640 | $100.0\% \pm 0.0\%$ | **TRIGGERED ($t = 3.6	ext{s}$)** | **SILENT (0 Alerts)** | **TRIGGERED ($t = 0.5	ext{s}$)** | Detected (Rate & State) |
| **T-3** | $1.0	ext{ s}$ | $1.0	ext{ Hz}$ | 320 | $98.8\% \pm 0.9\%$ | **TRIGGERED ($t = 4.8	ext{s}$)** | **SILENT (0 Alerts)** | **TRIGGERED ($t = 1.0	ext{s}$)** | Detected (Rate & State) |
| **T-4** | **$2.0	ext{ s}$** | **$0.5	ext{ Hz}$** | **160** | **$99.4\% \pm 0.6\%$** | **SILENT (0 Alerts)** | **SILENT (0 Alerts)** | **TRIGGERED ($t = 2.0	ext{s}$)** | **EVADED vs. Rate Thresholds ($H_1$ Supported)** |
| **T-5** | $5.0	ext{ s}$ | $0.2	ext{ Hz}$ | 64 | $68.1\% \pm 4.2\%$ | **SILENT (0 Alerts)** | **SILENT (0 Alerts)** | **TRIGGERED ($t = 5.0	ext{s}$)** | Evaded vs. Rate / Incomplete MitM |

```text
Injection Frequency vs. Detection & Retention:
Frequency   Retention Rate       Rate NIDS (Suricata)          State NIDS (Zeek arp.zeek)
 5.0 Hz     [100.0% ± 0.0%]      [ALERT: Tripped at t=1.2s]    [ALERT: Conflict on Frame 1]
 2.0 Hz     [100.0% ± 0.0%]      [ALERT: Tripped at t=3.6s]    [ALERT: Conflict on Frame 1]
 1.0 Hz     [ 98.8% ± 0.9%]      [ALERT: Tripped at t=4.8s]    [ALERT: Conflict on Frame 1]
 0.5 Hz     [ 99.4% ± 0.6%]      [SILENT - OPTIMAL EVASION]    [ALERT: Conflict on Frame 1]  <-- Optimal Evasion Boundary
 0.2 Hz     [ 68.1% ± 4.2%]      [SILENT - Cache Flushes]      [ALERT: Conflict on Frame 1]
```

### 2. State vs. Rate NIDS Detection Discrepancy
* **Rate-Based Evasion:** Standard NIDS rules (e.g., Suricata sliding windows) rely on volumetric thresholds ($> 1.0	ext{ Hz}$) to prevent alert fatigue from legitimate ARP bursts. At $0.5	ext{ Hz}$ ($\Delta t = 2.0	ext{s}$), the attacker injects only 2.5 frames per 5-second window, reliably sustaining $99.4\% \pm 0.6\%$ cache poisoning on commodity client endpoints while generating **0 alerts**.
* **The Operational Trade-off:** While state-based inspection (Zeek's `policy/protocols/arp.zeek`) flags conflicts on the very first packet, maintaining state tables across enterprise WLANs with mobile roaming, DHCP renewals, and randomized MACs (iOS/Android) causes prohibitive memory bloat and alert fatigue. Network operators routinely leave Layer-2 ARP tracking **disabled by default**, creating a systemic defensive blind spot.

---

## 🏛️ System Architecture

```text
                                [ Controlled Lab Subnet ]
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        ▼                                   ▼                                   ▼
[ Target Endpoint ]               [ Auditor Machine ]               [ Gateway Router ]
 192.168.18.51                      192.168.18.254                    192.168.18.1
 (macOS / iOS / Android)            (Scapy Engine + Flask Control)    (Huawei GPON ONT)
        │                                   │                                   │
        │                                   ├── [check_client_isolation.py]     │
        │                                   ├── [fingerprint_devices.py]        │
        │                                   ├── [arpspoof_server.py]            │
        │                                   └── [monitor_cache.py]              │
        │                                   │                                   │
        │◄────── Forged ARP Frame ──────────┤                                   │
        │  ("192.168.18.1 is at Auditor")   │                                   │
        │                                   ├──────── Forged ARP Frame ────────►│
        │                                   │  ("192.168.18.51 is at Auditor")  │
        │                                   │                                   │
        │────── Diverted Flow ─────────────►│────── Forwarded Flow ────────────►│
```

---

## 📂 Repository Directory Structure

```text
wlan-layer2-isolation-audit/
├── README.md                      # Academic repository documentation
├── LICENSE                        # MIT License
├── requirements.txt               # Python package dependencies
├── .gitignore                     # Git exclusion rules
├── paper/
│   ├── research_paper.md          # Complete empirical research paper (Markdown)
│   ├── research_paper.tex         # Academic IEEE double-column LaTeX manuscript
│   ├── generate_figures.py        # Publication vector figure rendering script
│   └── figures/                   # High-resolution vector figures (PDF & PNG)
├── src/
│   ├── check_client_isolation.py  # Layer-2 isolation auditor (dynamic subnet sweep)
│   ├── fingerprint_devices.py     # Asset profiler & randomized MAC detector
│   ├── arpspoof_server.py         # Asymmetric ARP engine & Flask instrumentation API
│   ├── arpspoof_ui.html           # Dark-mode dashboard UI
│   └── monitor_cache.py           # Kernel ARP cache retention monitor
├── data/
│   └── arpspoof_session_20261023_183806.json # Empirical telemetry data (1,200 redirected frames)
├── suricata/
│   ├── README.md                  # Suricata setup guide
│   └── local.rules                # Custom rate-limiting signature (sid:1000001)
└── zeek/
    ├── README.md                  # Zeek setup guide
    └── local.zeek                 # Script showing default vs policy/protocols/arp.zeek
```

---

## ⚡ Quickstart & Installation

### 1. Prerequisites
* Python 3.9+
* Root / Administrator privileges (required for raw packet socket creation)
* macOS or Linux (Ubuntu 22.04 LTS / Debian 12 recommended)

### 2. Setup Environment
```bash
# Clone the repository
git clone https://github.com/Arsalwali00/wlan-layer2-isolation-audit.git
cd wlan-layer2-isolation-audit

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🛠️ Toolchain Usage

### Step 1: Audit Station Isolation Status
Dynamically discovers your local network subnet and verifies whether peer stations can be reached laterally at Layer 2:
```bash
python3 src/check_client_isolation.py
```
* **Output:** Evaluates whether AP Client Isolation is `ENABLED` (secure) or `DISABLED` (vulnerable).

### Step 2: Fingerprint Active Devices
Inspects IEEE Organizationally Unique Identifiers (OUIs) and flags IEEE Locally Administered Address (LAA) randomized MAC privacy modes (common on iOS 14+ and Android 10+):
```bash
python3 src/fingerprint_devices.py
```

### Step 3: Run the Layer-2 Engine & Dashboard
Launch the decoupled packet injection engine and asynchronous control plane:
```bash
sudo python3 src/arpspoof_server.py
```
Then open `src/arpspoof_ui.html` in any modern web browser to view real-time traffic statistics, protocol distributions, and trigger automated JSON telemetry exports.

### Step 4: Monitor Endpoint ARP Cache Retention
Run the active polling routine on the target endpoint to reproduce the empirical retention rate benchmark:
```bash
python3 src/monitor_cache.py <GATEWAY_IP> <AUDITOR_MAC> [DURATION_SECONDS]
# Example:
python3 src/monitor_cache.py 192.168.18.1 3c:22:fb:00:11:22 160
```

---

## 🛡️ Defensive Engineering Blueprint

Remediating Layer-2 broadcast exposures requires a defense-in-depth model combining physical radio controls, switch intelligence, and cryptographic standards:

```text
+--------------------------------------------------------------------------+
|                       LAYER-2 DEFENSE IN DEPTH                           |
+--------------------------------------------------------------------------+
| 1. Radio Interface   : AP / Station Isolation (Drops Intra-BSS Traffic)  |
| 2. Switch Layer      : Dynamic ARP Inspection (DAI) + DHCP Snooping      |
| 3. Management Layer  : Out-of-Band VLAN (Port 80/22 Filtered on Wi-Fi)   |
| 4. Protocol Layer    : IEEE 802.11w Protected Management Frames (PMF)    |
+--------------------------------------------------------------------------+
```

1. **AP / Client Station Isolation:** Enable under WLAN Advanced Settings on access points. Filters intra-BSS unicast forwarding directly at the MAC controller, neutralizing lateral peer attacks entirely.
2. **Dynamic ARP Inspection (DAI) & DHCP Snooping:** Configured on access switches. Validates all incoming ARP frames against the authenticated DHCP snooping binding database (`MAC`, `IP`, `VLAN`, `Port`).
3. **IEEE 802.11w Protected Management Frames (PMF):** Standardized under WPA3. Cryptographically authenticates deauthentication and disassociation frames to prevent forced client re-associations.
4. **Out-of-Band Management:** Restrict router administrative web consoles (HTTP/HTTPS) to dedicated wired management VLANs rather than exposing them on client WLAN subnets.

---

## ⚖️ Ethical Scoping & Responsible Disclosure

* **Controlled Private Testbed:** All experiments were conducted within an isolated, researcher-owned laboratory environment.
* **Consent & Zero Third-Party Impact:** No unconsented, public, or production network traffic was intercepted, inspected, or retained.
* **RFC 5737 Compliance:** All internal MAC addresses and private endpoint IPs have been anonymized. Public destination IP addresses captured in flow logs have been sanitized and mapped to RFC 5737 benchmark documentation prefixes (`198.51.100.0/24` and `203.0.113.0/24`) while preserving real-world Autonomous System (AS) provider mappings for reproducible traffic categorization.
* **Remediation:** Vulnerabilities identified during testing were remediated on the testbed hardware immediately post-audit.

---

## 📖 BibTeX Citation

If you reference this research, diagnostic toolchain, or empirical evasion measurements in your academic work, please cite:

```bibtex
@misc{wali2026layer2isolation,
  author       = {Wali, Arslan},
  title        = {An Empirical Study on Layer-2 Station Isolation Deficits and Asymmetric Evasion Thresholds in Wireless Broadcast Domains},
  year         = {2026},
  month        = {October},
  howpublished = {\url{https://github.com/Arsalwali00/wlan-layer2-isolation-audit}},
  doi          = {10.5281/zenodo.23602802},
  url          = {https://doi.org/10.5281/zenodo.23602802},
  note         = {Applied Cybersecurity Research Case Study}
}
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
