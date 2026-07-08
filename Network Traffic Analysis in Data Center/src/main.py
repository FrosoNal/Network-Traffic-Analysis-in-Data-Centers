"""
main.py
-------
Entry point: parse the PCAP file, compute statistics, and generate
all the plots as PNG files in the current directory.
"""

from pcap_analysis import parse_pcap, compute_statistics
from plotting import (
    plot_cdf_packet_sizes,
    plot_cdf_flow_sizes,
    plot_bar_tcp_udp,
    plot_hist_packet_sizes,
    plot_pie_mice_elephant,
    plot_top20_flows,
)


def main():
    # 1) Parse the pcap file into raw counters.
    data = parse_pcap()

    # 2) Compute and print summary statistics.
    stats = compute_statistics(data)

    # 3) Generate all plots.
    print("\nGenerating plots ...")
    plot_cdf_packet_sizes(stats["psa"])
    plot_cdf_flow_sizes(stats["fsa"])
    plot_bar_tcp_udp(data["protocol_count"])
    plot_hist_packet_sizes(stats["psa"])
    plot_pie_mice_elephant(stats["mice"], stats["elephant"])
    plot_top20_flows(data["flows"])

    print("\n✔ Analysis complete!")


if __name__ == "__main__":
    main()
