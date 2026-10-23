# Cybersecurity CV, Portfolio, & Interview Guide — Arslan Wali (BS Computer Science)

This guide provides personalized resume bullet points, a LinkedIn project description, and technical interview talking points tailored for **Arslan Wali (BS Computer Science)** based on the empirical wireless network audit and research conducted in this lab.

---

## 1. Resume / CV Bullet Points

Add these directly under your **Projects** or **Technical Experience** section:

### Option A: Technical & Analytical Focus (Recommended for SOC Analyst / Security Engineer)
* **Wireless Network Isolation & Protocol Resilience Assessment**
  * Engineered an automated Python-based audit suite using Scapy and POSIX sockets to evaluate Layer-2 station isolation and broadcast domain boundaries across multi-vendor WLAN infrastructures.
  * Identified and documented critical network architecture vulnerabilities, including disabled AP station isolation, unencrypted HTTP administrative portals, and lateral host exposure across 20+ active endpoints.
  * Executed a controlled Layer-2 cache manipulation (MITRE ATT&CK T1557.002) in an authorized lab, quantitatively analyzing 1,200 diverted packets across TCP (38.2%) and UDP (61.4%) transport flows.
  * Developed an executive and technical remediation roadmap recommending IEEE 802.11w Protected Management Frames, Private VLANs (PVLANs), and Dynamic ARP Inspection (DAI) to enforce Zero Trust segmentation.

### Option B: Concise 2-Bullet Version (For tight resume space)
* **Wireless Security Auditor | Research Case Study**
  * Built an automated Python scanning tool to evaluate IEEE 802.11 AP Client Isolation and ARP cache poisoning resilience across SOHO and enterprise wireless hardware.
  * Formulated remediation guidelines to prevent lateral movement and credential theft, implementing Station Isolation, Dynamic ARP Inspection (DAI), and out-of-band management segmentation.

---

## 2. LinkedIn Project Description

**Project Title:** Wireless Station Isolation & Layer-2 Exposure Research  
**Skills:** Network Security, Python (Scapy), Wi-Fi Architecture (IEEE 802.11), Vulnerability Assessment, MITRE ATT&CK (T1557.002), Network Defense.

**Description:**
> Conducted an empirical vulnerability assessment examining how disabled Client/Station Isolation on wireless access points exposes connected endpoints to Layer-2 interception and lateral surveillance. Built an automated audit toolchain to profile subnets, detect missing isolation policies, and measure traffic diversion under simulated adversary conditions. Quantitatively analyzed 1,200 intercepted packet flows and authored an empirical research paper outlining engineering mitigations, including Private VLANs, Dynamic ARP Inspection (DAI), and 802.11w PMF.

---

## 3. Interview Talking Points & Questions

When hiring managers or technical interviewers ask you about your hands-on security experience, use these structured answers:

### Q1: "Tell me about a hands-on network security assessment you have conducted."
> **Answer:**  
> *"Recently, I conducted a hands-on audit evaluating wireless network segmentation across two different router architectures—a TP-Link SOHO router and a Huawei GPON ONT. I developed custom Python diagnostic scripts using Scapy to test whether the access points enforced Client Station Isolation. I discovered that on both networks, Client Isolation was disabled by default, exposing over 20 connected endpoints to lateral reconnaissance. In an authorized lab test, I demonstrated that an auditor machine could divert 1,200 packets in under three minutes simply by exploiting the unauthenticated nature of ARP. I documented the findings, analyzed the destination IP metadata, and delivered a defensive blueprint detailing how to remediate the risk using AP Isolation and Dynamic ARP Inspection."*

---

### Q2: "What is ARP Spoofing, and why does it work?"
> **Answer:**  
> *"ARP was designed in RFC 826 with zero cryptographic authentication. Operating systems maintain an ARP cache mapping IP addresses to physical MAC addresses. Because ARP is stateless and trusts unsolicited replies, any host on the local broadcast domain can broadcast an ARP reply claiming that its MAC address owns the default gateway IP. Devices automatically update their memory tables without verification, creating an Adversary-in-the-Middle position at Layer 2."*

---

### Q3: "How do you defend against ARP Spoofing in an enterprise?"
> **Answer:**  
> *"Defense requires a defense-in-depth approach at the networking hardware level:
> 1. **On Wireless:** Enable **Client / AP Station Isolation** on access points so the radio interface drops peer-to-peer traffic.
> 2. **On Managed Switches:** Deploy **Dynamic ARP Inspection (DAI)** coupled with **DHCP Snooping** to drop forged ARP replies that do not match the trusted binding database.
> 3. **Protocol Layer:** Enforce **802.1X Network Access Control (NAC)** and **WPA3**, which mandates IEEE 802.11w Protected Management Frames to prevent management frame tampering."*

---

## 4. Key Metrics to Mention
Whenever discussing this project, referencing exact numbers demonstrates real-world empirical rigor:
* **2 distinct hardware platforms tested:** TP-Link TL-WR940N and Huawei GPON ONT.
* **160-second test window:** 160 ARP control frames injected.
* **1,200 diverted packets measured:** 737 UDP (61.4%), 458 TCP (38.2%), 5 ICMP/Other (0.4%).
* **20+ active endpoints protected:** By recommending immediate AP Isolation enforcement.
