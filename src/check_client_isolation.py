#!/usr/bin/env python3
"""
Dynamic Network Isolation & ARP Exposure Auditor
-------------------------------------------------
Audits any connected network dynamically (without hardcoded subnets or IPs)
to determine if Wireless Client/AP Isolation is missing and whether the network
is vulnerable to peer-to-peer attacks like ARP Spoofing.

Author: Cybersecurity Assessment Suite
Platform: macOS / Linux
"""

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import sys


def run_cmd(cmd_list):
    """Executes a system command and returns trimmed stdout string."""
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return ""


def get_default_interface_and_gateway():
    """Dynamically determines the active network interface and default gateway."""
    gateway_ip = None
    interface_name = None

    # macOS route check
    route_out = run_cmd(["route", "-n", "get", "default"])
    if route_out:
        for line in route_out.splitlines():
            line = line.strip()
            if line.startswith("gateway:"):
                gateway_ip = line.split("gateway:")[1].strip()
            elif line.startswith("interface:"):
                interface_name = line.split("interface:")[1].strip()

    # Fallback for Linux or if route command differs
    if not gateway_ip or not interface_name:
        ip_route = run_cmd(["ip", "route", "show", "default"])
        if ip_route:
            # Format: default via 192.168.1.1 dev wlan0 ...
            tokens = ip_route.split()
            if "via" in tokens and "dev" in tokens:
                gateway_ip = tokens[tokens.index("via") + 1]
                interface_name = tokens[tokens.index("dev") + 1]

    # Fallback socket method to find local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
        s.close()
    except Exception:
        outbound_ip = None

    return interface_name, gateway_ip, outbound_ip


def get_interface_network(interface_name, outbound_ip):
    """Extracts IP, netmask, and calculates the exact CIDR network dynamically."""
    ifconfig_out = run_cmd(["ifconfig", interface_name])
    local_ip = outbound_ip
    netmask = None

    # Parse inet line: inet 192.168.0.111 netmask 0xffffff00 broadcast 192.168.0.255
    for line in ifconfig_out.splitlines():
        line = line.strip()
        if line.startswith("inet ") and not line.startswith("inet 127."):
            parts = line.split()
            local_ip = parts[1]
            if "netmask" in parts:
                raw_mask = parts[parts.index("netmask") + 1]
                # Convert hex mask like 0xffffff00 to decimal or let ipaddress parse
                if raw_mask.startswith("0x"):
                    netmask = str(socket.inet_ntoa(bytes.fromhex(raw_mask[2:])))
                else:
                    netmask = raw_mask
            break

    if not local_ip:
        local_ip = outbound_ip or "127.0.0.1"
    if not netmask:
        netmask = "255.255.255.0"

    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    return local_ip, netmask, network


def ping_host(ip_str):
    """Sends a single fast ping to trigger an ARP table entry."""
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", "400", ip_str] if is_win else ["ping", "-c", "1", "-W", "400", ip_str]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ip_str, (res.returncode == 0)
    except Exception:
        return ip_str, False


def scan_network_hosts(network, local_ip):
    """Dynamically sweeps the network to populate the local ARP table."""
    # Cap scan size to avoid overwhelming huge /16 subnets (default to /24 slice around local IP)
    if network.num_addresses > 256:
        # Scan the /24 neighborhood of local IP
        octets = local_ip.split(".")[:3]
        target_ips = [f"{octets[0]}.{octets[1]}.{octets[2]}.{i}" for i in range(1, 255)]
        print(f"[*] Large subnet detected ({network}). Scanning local /24 neighborhood ({len(target_ips)} hosts)...")
    else:
        target_ips = [str(ip) for ip in network.hosts()]
        print(f"[*] Scanning {len(target_ips)} hosts on subnet {network}...")

    # Fast multi-threaded ping
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in target_ips}
        for future in concurrent.futures.as_completed(futures):
            future.result()


def parse_resolved_arp(network, local_ip, gateway_ip):
    """Inspects OS ARP table and isolates active peer devices from gateway and local host."""
    arp_out = run_cmd(["arp", "-an"])
    peers = []
    gateway_mac = "Unknown"

    regex = r"\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([0-9a-fA-F:]+)"
    for match in re.finditer(regex, arp_out):
        ip = match.group(1)
        mac = match.group(2).lower()

        if "incomplete" in mac or mac == "ff:ff:ff:ff:ff:ff":
            continue

        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj not in network:
            continue

        if ip == gateway_ip:
            gateway_mac = mac
        elif ip != local_ip:
            peers.append({"ip": ip, "mac": mac})

    peers.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return peers, gateway_mac


def main():
    print("=" * 70)
    print("      DYNAMIC NETWORK ISOLATION & ARP EXPOSURE AUDITOR")
    print("=" * 70)

    # 1. Discover network topology dynamically
    iface, gateway_ip, outbound_ip = get_default_interface_and_gateway()
    if not iface or not gateway_ip:
        print("[!] Error: Could not determine active network interface or default gateway.")
        sys.exit(1)

    local_ip, netmask, network = get_interface_network(iface, outbound_ip)

    print(f"[*] Active Interface:    {iface}")
    print(f"[*] Local Auditor IP:    {local_ip}")
    print(f"[*] Subnet Mask:         {netmask} (CIDR: {network})")
    print(f"[*] Default Gateway:     {gateway_ip}")
    print("-" * 70)

    # 2. Sweep to test Layer 2 / Layer 3 reachability
    scan_network_hosts(network, local_ip)

    # 3. Analyze results from ARP table
    peers, gateway_mac = parse_resolved_arp(network, local_ip, gateway_ip)

    print("-" * 70)
    print(f"[*] Default Gateway MAC: {gateway_mac}")
    print(f"[*] Discovered Peers:    {len(peers)} other client device(s)\n")

    if peers:
        print(f"{'Peer IP Address':<20} {'Resolved MAC Address':<25}")
        print("-" * 45)
        for peer in peers:
            print(f"{peer['ip']:<20} {peer['mac']:<25}")
        print("-" * 70)

    # 4. Final Verdict and Security Assessment
    print("=" * 70)
    print("AUDIT ASSESSMENT VERDICT:")
    if len(peers) > 0:
        print("  STATUS: [ VULNERABLE ] - CLIENT ISOLATION IS DISABLED")
        print("=" * 70)
        print(f"  • Reason: Your machine was able to discover and resolve Layer 2 MAC")
        print(f"    addresses for {len(peers)} peer device(s) on this network.")
        print("  • Risk:")
        print("    - Network is susceptible to ARP Spoofing / Man-in-the-Middle (MitM).")
        print("    - Peer-to-peer lateral port scanning and credential harvesting enabled.")
        print("  • Recommended Action:")
        print(f"    Log into the AP management console ({gateway_ip}) and enable:")
        print("    'AP Isolation' / 'Client Isolation' / 'Station Isolation'.")
    else:
        print("  STATUS: [ SECURE / PASS ] - CLIENT ISOLATION APPEARS ACTIVE")
        print("=" * 70)
        print("  • Reason: Zero peer client devices could be resolved at Layer 2.")
        print("  • The Access Point appears to be dropping client-to-client frames.")
    print("=" * 70)


if __name__ == "__main__":
    main()
