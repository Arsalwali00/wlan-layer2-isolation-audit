#!/usr/bin/env python3
"""
Network Device Fingerprinting & Asset Profiler
----------------------------------------------
Audit Purpose:
Profiles active devices discovered on the local network by analyzing:
1. MAC Address Hardware OUI & Private/Randomized MAC detection (IEEE 802).
2. Reverse DNS hostname resolution.
3. Diagnostic listening port detection (HTTP, HTTPS, SSH, SMB, DNS, RDP).
4. Device Type / Operating System inference for security risk profiling.

Platform: macOS / Linux (Python 3 standard library)
"""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import sys

# Common well-known diagnostic ports
PROBE_PORTS = {
    22: "SSH (Linux/Mac/Router)",
    53: "DNS (Router/DNS Server)",
    80: "HTTP (Web Management/Dev)",
    443: "HTTPS (Web Management)",
    445: "SMB (Windows File Sharing)",
    3389: "RDP (Windows Remote Desktop)",
    5000: "UPnP / Docker / Flask",
    8080: "HTTP-Proxy / Alt-Web",
}

# Known vendor OUIs for common networking equipment
KNOWN_OUIS = {
    "cc:32:e5": "TP-Link Technologies",
    "f4:f2:6d": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "a0:70:b7": "Huawei Technologies (GPON/ONT Router)",
    "00:14:bf": "Cisco-Linksys",
    "00:18:0a": "Cisco Systems",
    "00:0c:29": "VMware Virtual NIC",
    "00:50:56": "VMware Virtual NIC",
    "08:00:27": "Oracle VirtualBox",
    "dc:a6:32": "Raspberry Pi Trading",
    "b8:27:eb": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Trading",
    "3c:22:fb": "Apple Inc.",
    "ac:bc:32": "Apple Inc.",
    "f0:18:98": "Apple Inc.",
}


def check_port(ip, port, timeout=0.8):
    """Attempts a non-intrusive TCP connection to test if a port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return port, (result == 0)
    except Exception:
        return port, False


def scan_device_ports(ip):
    """Scans diagnostic ports for a target IP concurrently."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, ip, p): p for p in PROBE_PORTS}
        for future in concurrent.futures.as_completed(futures):
            p, is_open = future.result()
            if is_open:
                open_ports.append(p)
    return sorted(open_ports)


def analyze_mac(mac):
    """
    Analyzes MAC address:
    - Checks IEEE locally administered address (LAA) bit for Private/Randomized MACs
    - Looks up known vendor OUIs
    """
    clean_mac = mac.lower().strip()
    parts = clean_mac.split(":")
    if len(parts) < 3:
        return "Unknown MAC", False

    # Check the U/L (Universal/Local) bit in the first byte
    # If bit 1 (0x02) is set, it's a locally administered / randomized address
    try:
        first_byte = int(parts[0], 16)
        is_randomized = bool(first_byte & 0x02)
    except ValueError:
        is_randomized = False

    oui = f"{parts[0]}:{parts[1]}:{parts[2]}"
    vendor = KNOWN_OUIS.get(oui)

    if vendor:
        vendor_desc = vendor
    elif is_randomized:
        vendor_desc = "Private / Randomized MAC (iOS, Android, or Win/Mac Privacy)"
    else:
        vendor_desc = f"Standard Hardware OUI ({oui.upper()})"

    return vendor_desc, is_randomized


def resolve_hostname(ip):
    """Attempts reverse DNS lookup for a device IP."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return "No DNS PTR record"


def infer_device_type(ip, open_ports, is_gateway, is_randomized):
    """Infers device category and likely OS profile based on open services and MAC properties."""
    if is_gateway:
        return "Network Gateway / Router / AP"
    if 445 in open_ports or 3389 in open_ports:
        return "Windows PC / Server (SMB/RDP active)"
    if 22 in open_ports and not (80 in open_ports or 443 in open_ports):
        return "Linux / macOS Workstation (SSH active)"
    if 80 in open_ports or 443 in open_ports:
        return "Web Server / Embedded Appliance"
    if is_randomized and not open_ports:
        return "Smartphone / Tablet (Locked-down endpoint with Private MAC)"
    if not open_ports:
        return "Client Endpoint (Firewall active / all ports filtered)"
    return "Generic Network Host"


def get_active_devices_from_arp():
    """Reads current resolved devices from OS ARP table."""
    devices = []
    try:
        arp_out = subprocess.check_output(["arp", "-an"], text=True)
        regex = r"\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([0-9a-fA-F:]+)"
        for match in re.finditer(regex, arp_out):
            ip = match.group(1)
            mac = match.group(2).lower()
            if "incomplete" in mac or mac == "ff:ff:ff:ff:ff:ff":
                continue
            devices.append({"ip": ip, "mac": mac})
    except Exception as e:
        print(f"[!] Error reading ARP table: {e}", file=sys.stderr)

    return sorted(devices, key=lambda d: ipaddress.IPv4Address(d["ip"]))


def get_gateway_ip():
    """Identifies default gateway."""
    try:
        out = subprocess.check_output(["route", "-n", "get", "default"], text=True)
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split("gateway:")[1].strip()
    except Exception:
        pass
    return "192.168.0.1"


def main():
    print("=" * 75)
    print("        NETWORK ASSET FINGERPRINTING & TARGET PROFILER")
    print("=" * 75)

    gateway_ip = get_gateway_ip()
    network_prefix = ".".join(gateway_ip.split(".")[:3])
    
    # Quick sweep to wake up all active devices in the ARP cache
    print(f"[*] Sweeping subnet {network_prefix}.0/24 to discover active devices...")
    ips = [f"{network_prefix}.{i}" for i in range(1, 255)]
    def quick_ping(ip):
        try:
            subprocess.run(["ping", "-c", "1", "-W", "300", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        list(ex.map(quick_ping, ips))

    devices = get_active_devices_from_arp()

    if not devices:
        print("[!] No resolved devices found in ARP table. Run check_client_isolation.py first.")
        sys.exit(1)

    print(f"[*] Default Gateway: {gateway_ip}")
    print(f"[*] Profiling {len(devices)} active network endpoint(s)...\n")

    for idx, dev in enumerate(devices, 1):
        ip = dev["ip"]
        mac = dev["mac"]
        is_gw = (ip == gateway_ip)

        vendor, is_randomized = analyze_mac(mac)
        hostname = resolve_hostname(ip)
        open_ports = scan_device_ports(ip)
        dev_type = infer_device_type(ip, open_ports, is_gw, is_randomized)

        print("-" * 75)
        print(f"Device #{idx}: {ip} {'[GATEWAY]' if is_gw else '[CLIENT PEER]'}")
        print(f"  • MAC Address:       {mac}")
        print(f"  • Hardware Vendor:   {vendor}")
        print(f"  • Hostname / PTR:    {hostname}")
        print(f"  • Inferred Profile:  {dev_type}")

        if open_ports:
            ports_desc = [f"{p} ({PROBE_PORTS.get(p, 'Unknown')})" for p in open_ports]
            print(f"  • Open TCP Services: {', '.join(ports_desc)}")
        else:
            print("  • Open TCP Services: None detected (Ports filtered by host firewall)")

    print("=" * 75)
    print("SECURITY SPECIALIST SUMMARY:")
    print("  1. Devices with open ports (e.g., HTTP 80, SMB 445, SSH 22) represent")
    print("     direct service attack surfaces.")
    print("  2. Devices with 'Private / Randomized MAC' are typically smartphones or")
    print("     modern laptops using privacy features.")
    print("  3. Because Client Isolation is disabled, all these endpoints are directly")
    print("     reachable by any peer on the Wi-Fi.")
    print("=" * 75)


if __name__ == "__main__":
    main()
