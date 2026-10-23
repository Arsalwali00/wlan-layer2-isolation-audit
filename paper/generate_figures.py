#!/usr/bin/env python3
"""
Publication Figure Generator for:
"An Empirical Study on Layer-2 Station Isolation Deficits and Asymmetric Evasion Thresholds in Wireless Broadcast Domains"
Author: Arslan Wali
"""

import os
import matplotlib.pyplot as plt
import numpy as np

# Ensure output directory exists
os.makedirs("paper/figures", exist_ok=True)

# Set high-quality IEEE publication styling
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 9,
    "figure.titlesize": 13,
    "figure.autolayout": True,
    "lines.linewidth": 1.8,
    "lines.markersize": 7,
})

# ==============================================================================
# FIGURE 1: Evasion Threshold & Cache Retention Trade-Off Curve (Table 1)
# ==============================================================================
def generate_figure_1():
    trials = ["T-5 (0.2 Hz)", "T-4 (0.5 Hz)", "T-3 (1.0 Hz)", "T-2 (2.0 Hz)", "T-1 (5.0 Hz)"]
    freqs = [0.2, 0.5, 1.0, 2.0, 5.0]
    retention_means = [68.1, 99.4, 98.8, 100.0, 100.0]
    retention_stds = [4.2, 0.6, 0.9, 0.0, 0.0]
    suricata_alert_times = [None, None, 4.8, 3.6, 1.2]  # None = Silent/Evaded

    fig, ax1 = plt.subplots(figsize=(7.2, 4.2), dpi=300)

    color_ret = "#1f77b4"
    ax1.set_xlabel("Injection Frequency $f$ (Hz) [Log Scale]", fontweight="bold")
    ax1.set_xscale("log")
    ax1.minorticks_off()
    ax1.set_xticks(freqs)
    ax1.set_xticklabels(["0.2", "0.5", "1.0", "2.0", "5.0"])
    ax1.set_xlim(0.15, 6.5)
    ax1.set_ylabel("Kernel ARP Cache Retention Rate (%)", color=color_ret, fontweight="bold")
    line1 = ax1.errorbar(
        freqs, retention_means, yerr=retention_stds, fmt="-o", color=color_ret,
        ecolor="#6baed6", elinewidth=2, capsize=5, capthick=1.5, label="Cache Retention Rate (Mean $\\pm \\sigma$)"
    )
    ax1.tick_params(axis="y", labelcolor=color_ret)
    ax1.set_ylim(55, 105)
    ax1.grid(True, which="both", linestyle="--", alpha=0.3)

    # Right axis: Suricata alert latency
    ax2 = ax1.twinx()
    color_nids = "#d62728"
    ax2.set_ylabel("Suricata 7.0 Detection Latency (s)", color=color_nids, fontweight="bold")
    
    # Plot points for detected trials
    det_freqs = [1.0, 2.0, 5.0]
    det_times = [4.8, 3.6, 1.2]
    line2 = ax2.plot(det_freqs, det_times, "--s", color=color_nids, label="Suricata Rate Alert Time ($t$)")
    ax2.tick_params(axis="y", labelcolor=color_nids)
    ax2.set_ylim(0, 6.0)

    # Shaded Asymmetric Evasion Boundary Window
    ax1.axvspan(0.35, 0.75, color="#2ca02c", alpha=0.15, label="Optimal Evasion Window ($H_1$)")
    ax1.annotate(
        "Optimal Evasion Window ($H_1$ Supported)\n• 99.4% Cache Retention\n• 0 NIDS Alerts (Rate Silent)",
        xy=(0.5, 99.4), xytext=(0.28, 80),
        arrowprops=dict(facecolor="#2ca02c", shrink=0.08, width=1.5, headwidth=6),
        fontsize=8.5, fontweight="semibold", bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#2ca02c", lw=1.2)
    )

    # Unify legends
    lines = [line1, line2[0]]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="lower left", framealpha=0.9)

    plt.title("Empirical Asymmetric Evasion Threshold Curve ($N=3$ Runs, 2,400 Checkpoints)", pad=12)
    plt.tight_layout()
    plt.savefig("paper/figures/fig1_evasion_retention_tradeoff.pdf")
    plt.savefig("paper/figures/fig1_evasion_retention_tradeoff.png")
    plt.close()
    print("[+] Generated: paper/figures/fig1_evasion_retention_tradeoff (PDF & PNG)")

# ==============================================================================
# FIGURE 2: Diverted Protocol Composition & AS Leakage (Section 5.3 & Table 2)
# ==============================================================================
def generate_figure_2():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 3.8), dpi=300)

    # Subplot A: Protocol Composition
    labels_proto = ["UDP\n(61.4% / 737 pkts)", "TCP\n(38.2% / 458 pkts)", "ICMP/Other\n(0.4% / 5 pkts)"]
    sizes_proto = [737, 458, 5]
    colors_proto = ["#3498db", "#2ecc71", "#e74c3c"]
    explode = (0.05, 0, 0)

    wedges, texts, autotexts = ax1.pie(
        sizes_proto, explode=explode, labels=labels_proto, autopct="%1.1f%%",
        startangle=140, colors=colors_proto, textprops=dict(size=9)
    )
    for at in autotexts:
        at.set_color("white")
        at.set_weight("bold")
    ax1.set_title("(a) Diverted Flow Protocol Breakdown\n(1,200 Total Diverted Packets)", fontsize=10, pad=10)

    # Subplot B: Top Autonomous Systems (AS) Traffic Volume
    as_providers = [
        "Akamai Edge\n(AS20940)",
        "Google Cloud\n(AS15169)",
        "Google Search\n(AS15169)",
        "Cloudflare Edge\n(AS13335)",
        "Regional ISP\n(AS55836)",
        "Google Telemetry\n(AS15169)"
    ]
    packet_counts = [55, 31, 16, 27, 11, 17]  # Consolidated Cloudflare (14+13) & Google telemetry (8+9)
    y_pos = np.arange(len(as_providers))

    bars = ax2.barh(y_pos, packet_counts, color="#34495e", edgecolor="#2c3e50", height=0.6)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(as_providers, fontsize=8.5)
    ax2.invert_yaxis()  # Top provider on top
    ax2.set_xlabel("Captured Packet Count (Flow Metadata)", fontsize=9.5)
    ax2.set_title("(b) Autonomous System (AS) Destination Profiling", fontsize=10, pad=10)
    ax2.grid(axis="x", linestyle="--", alpha=0.3)

    # Annotate bar values
    for bar in bars:
        width = bar.get_width()
        ax2.text(width + 1.2, bar.get_y() + bar.get_height()/2, f"{int(width)} pkts",
                 va="center", ha="left", fontsize=8.5, color="#2c3e50", fontweight="bold")
    ax2.set_xlim(0, 68)

    plt.tight_layout()
    plt.savefig("paper/figures/fig2_protocol_as_distribution.pdf")
    plt.savefig("paper/figures/fig2_protocol_as_distribution.png")
    plt.close()
    print("[+] Generated: paper/figures/fig2_protocol_as_distribution (PDF & PNG)")

if __name__ == "__main__":
    generate_figure_1()
    generate_figure_2()
