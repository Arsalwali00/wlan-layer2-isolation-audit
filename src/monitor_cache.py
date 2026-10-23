#!/usr/bin/env python3
"""
Continuous Target Kernel Cache Polling Routine
----------------------------------------------
Audits and logs target kernel ARP cache entries at 1.0 Hz to measure
empirical cache retention during parameterized ARP injection trials.

Cross-platform support: macOS / BSD and Linux.
"""

import subprocess
import time
import sys
import platform

def sample_gateway_mac(gateway_ip):
    """Queries local kernel ARP table for current gateway hardware address."""
    system = platform.system().lower()
    
    if system == "darwin":
        # macOS / BSD syntax
        cmd = ["arp", "-n", gateway_ip]
    else:
        # Linux syntax
        cmd = ["ip", "-4", "neigh", "show", gateway_ip]
        
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            if gateway_ip in line:
                tokens = line.split()
                if system == "darwin":
                    # Format: ? (192.168.18.1) at 00:11:22:33:44:55 on en0 ...
                    if len(tokens) >= 4 and "at" in tokens:
                        return tokens[tokens.index("at") + 1].lower()
                    return tokens[2].lower() if len(tokens) >= 3 else None
                else:
                    # Linux Format: 192.168.18.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                    if "lladdr" in tokens:
                        return tokens[tokens.index("lladdr") + 1].lower()
    except Exception:
        pass
    return None

def run_retention_benchmark(gateway_ip, auditor_mac, duration_sec=160):
    print(f"[*] Starting ARP cache retention monitor for Gateway: {gateway_ip}")
    print(f"[*] Expected Auditor MAC (Poisoned state): {auditor_mac.lower()}")
    print(f"[*] Benchmark Duration: {duration_sec} seconds (1.0 Hz sampling)...\n")
    
    checkpoints = 0
    poisoned_hits = 0
    start_time = time.time()
    
    try:
        while (time.time() - start_time) < duration_sec:
            elapsed = int(time.time() - start_time)
            current_mac = sample_gateway_mac(gateway_ip)
            is_poisoned = (current_mac == auditor_mac.lower())
            
            if is_poisoned:
                poisoned_hits += 1
            checkpoints += 1
            
            status = "POISONED" if is_poisoned else "GENUINE/REVERTED"
            print(f"[{elapsed:03d}s] Checkpoint {checkpoints:03d}: Gateway MAC = {current_mac} -> [{status}]")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[!] Benchmark interrupted by user.")

    retention_rate = (poisoned_hits / checkpoints * 100.0) if checkpoints > 0 else 0.0
    print(f"\n{'='*55}")
    print(f" BENCHMARK RESULTS")
    print(f"{'='*55}")
    print(f"Total Checkpoints  : {checkpoints}")
    print(f"Poisoned Hits      : {poisoned_hits}")
    print(f"Cache Retention    : {retention_rate:.2f}%")
    print(f"{'='*55}")
    return retention_rate, checkpoints

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 monitor_cache.py <GATEWAY_IP> <AUDITOR_MAC> [DURATION_SEC]")
        print("Example: python3 monitor_cache.py 192.168.18.1 3c:22:fb:xx:yy:zz 160")
        sys.exit(1)
        
    gw = sys.argv[1]
    mac = sys.argv[2]
    dur = int(sys.argv[3]) if len(sys.argv) > 3 else 160
    run_retention_benchmark(gw, mac, dur)
