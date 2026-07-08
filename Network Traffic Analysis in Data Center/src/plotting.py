"""
plotting.py
-----------
All chart-generating functions:
  1. plot_cdf_packet_sizes
  2. plot_cdf_flow_sizes
  3. plot_bar_tcp_udp
  4. plot_hist_packet_sizes
  5. plot_pie_mice_elephant
  6. plot_top20_flows
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from config import BLUE, ORANGE, GREEN
from utils import save_fig


def plot_cdf_packet_sizes(psa):
    """CDF (cumulative distribution function) of packet sizes."""
    data_sorted = np.sort(psa)
    y = np.arange(1, len(data_sorted) + 1) / len(data_sorted)

    plt.figure(figsize=(8, 5))
    plt.plot(data_sorted, y, linewidth=2, color=BLUE)
    plt.xlabel("Packet Size (bytes)", fontsize=13)
    plt.ylabel("CDF", fontsize=13)
    plt.title("CDF of Packet Size", fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.xscale("log")
    save_fig("cdf_packet_sizes.png")


def plot_cdf_flow_sizes(fsa):
    """CDF (cumulative distribution function) of flow sizes."""
    data_sorted = np.sort(fsa)
    y = np.arange(1, len(data_sorted) + 1) / len(data_sorted)

    plt.figure(figsize=(8, 5))
    plt.plot(data_sorted, y, linewidth=2, color=BLUE)
    plt.xlabel("Flow Size (bytes)", fontsize=13)
    plt.ylabel("CDF", fontsize=13)
    plt.title("CDF of Flow Size", fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    plt.xscale("log")
    save_fig("cdf_flow_sizes.png")


def plot_bar_tcp_udp(protocol_count):
    """Bar chart comparing TCP vs UDP packet counts."""
    fig, ax = plt.subplots(figsize=(7, 5))
    cats = ["TCP", "UDP"]
    vals = [protocol_count["TCP"], protocol_count["UDP"]]

    bars = ax.bar(cats, vals, color=[BLUE, ORANGE], width=0.5,
                  edgecolor="white", linewidth=1.2)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 4000,
                 f"{v:,}\n({100*v/sum(vals):.1f}%)", ha="center", va="bottom",
                 fontsize=12, fontweight="bold")

    ax.set_ylabel("Number of Packets", fontsize=13)
    ax.set_title("Packet Distribution by Protocol", fontsize=14, fontweight='bold')
    ax.set_ylim(0, max(vals) * 1.18)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x/1e3:.0f}K"))
    ax.spines[['top', 'right']].set_visible(False)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    save_fig("bar_tcp_udp.png")


def plot_hist_packet_sizes(psa):
    """Histogram of packet size values with percentage labels."""
    fig, ax = plt.subplots(figsize=(7, 5))
    unique, counts = np.unique(psa, return_counts=True)

    ax.bar(unique.astype(str), counts, color=BLUE, edgecolor="white", linewidth=0.8)
    ax.set_xlabel("Packet Size (bytes)", fontsize=13)
    ax.set_ylabel("Packet Count", fontsize=13)
    ax.set_title("Histogram of Packet Size", fontsize=14, fontweight='bold')
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x/1e3:.0f}K"))
    ax.spines[['top', 'right']].set_visible(False)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    for bar, v in zip(ax.patches, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2000,
                 f"{100*v/len(psa):.1f}%", ha='center', va='bottom', fontsize=9, color='#333')
    save_fig("hist_packet_sizes.png")


def plot_pie_mice_elephant(mice, elephant):
    """Pie chart of mice vs elephant flow proportions."""
    fig, ax = plt.subplots(figsize=(6, 6))
    wedges, texts, autotexts = ax.pie(
        [mice, elephant],
        labels=["Mice flows\n(< 100 KB)", "Elephant flows\n(≥ 100 KB)"],
        autopct="%1.1f%%", colors=[BLUE, ORANGE], startangle=90,
        wedgeprops=dict(edgecolor='white', linewidth=2), textprops=dict(fontsize=12)
    )
    for at in autotexts:
        at.set_fontsize(13); at.set_fontweight('bold'); at.set_color('white')

    ax.set_title("Mice vs Elephant Flows\n(threshold: 100 KB)", fontsize=14, fontweight='bold')
    ax.annotate(f"Mice: {mice:,}  |  Elephant: {elephant:,}", xy=(0, -1.35),
                ha='center', fontsize=11, color='#444')
    save_fig("pie_mice_elephant.png")


def plot_top20_flows(flows):
    """Horizontal bar chart of the 20 largest flows by total bytes."""
    sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)[:20]
    labels = [f"{i+1}. {k[4]}  {k[2]}→{k[3]}" for i, (k, v) in enumerate(sorted_flows)]
    values = [v / 1024 for _, v in sorted_flows]
    colors_top = [ORANGE if k[4] == "TCP" else GREEN for k, v in sorted_flows]

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(range(len(labels)), values, color=colors_top, edgecolor='white', linewidth=0.8)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel("Flow Size (KB)", fontsize=12)
    ax.set_title("Top-20 Largest Flows", fontsize=14, fontweight='bold')
    ax.spines[['top', 'right']].set_visible(False)
    ax.grid(axis='x', alpha=0.3, linestyle='--')

    for bar, v in zip(bars, values):
        ax.text(bar.get_width() + 10, bar.get_y() + bar.get_height() / 2,
                 f"{v:.0f} KB", va='center', fontsize=8)

    tcp_p = mpatches.Patch(color=ORANGE, label='TCP')
    udp_p = mpatches.Patch(color=GREEN, label='UDP')
    ax.legend(handles=[tcp_p, udp_p], loc='lower right', fontsize=10)
    save_fig("top20_flows.png")
