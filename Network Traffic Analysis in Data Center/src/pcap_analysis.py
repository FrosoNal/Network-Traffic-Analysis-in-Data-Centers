"""
pcap_analysis.py
----------------
Parses the PCAP file into per-flow byte counts and packet sizes,
and computes summary statistics (packet/flow size distributions,
protocol split, mice vs elephant flow classification).
"""

from collections import defaultdict

import dpkt
import numpy as np

from utils import ip_to_str, open_pcap

MICE_ELEPHANT_THRESHOLD = 100_000  # bytes; flows >= this are "elephant" flows


def parse_pcap():
    """
    Read the PCAP file and aggregate traffic statistics.

    Returns a dict with:
        flows          : {flow_key: total_bytes}
        packet_sizes   : list of packet lengths (bytes)
        protocol_count : {"TCP": n, "UDP": n}
        total_packets  : total number of packets in the capture
        ip_packets     : number of packets that were IP packets
    """
    flows          = defaultdict(int)
    packet_sizes   = []
    protocol_count = {"TCP": 0, "UDP": 0}
    total_packets  = 0
    ip_packets     = 0

    f_pcap, tar_obj = open_pcap()

    try:
        pcap = dpkt.pcap.Reader(f_pcap)
        for timestamp, buf in pcap:
            total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue  # skip malformed frames
            if not isinstance(eth.data, dpkt.ip.IP):
                continue  # skip non-IP traffic

            ip = eth.data
            ip_packets += 1

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto = "TCP"; l4 = ip.data; protocol_count["TCP"] += 1
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto = "UDP"; l4 = ip.data; protocol_count["UDP"] += 1
            else:
                continue  # skip other L4 protocols

            flow_key = (ip_to_str(ip.src), ip_to_str(ip.dst), l4.sport, l4.dport, proto)
            packet_len = len(buf)
            packet_sizes.append(packet_len)
            flows[flow_key] += packet_len
    finally:
        f_pcap.close()
        if tar_obj:
            tar_obj.close()

    return dict(
        flows=flows,
        packet_sizes=packet_sizes,
        protocol_count=protocol_count,
        total_packets=total_packets,
        ip_packets=ip_packets,
    )


def compute_statistics(data):
    """
    Compute derived statistics (numpy arrays, mice/elephant counts)
    from the raw parsing output, print a summary report, and return
    everything needed for plotting.
    """
    flows          = data["flows"]
    packet_sizes   = data["packet_sizes"]
    protocol_count = data["protocol_count"]
    total_packets  = data["total_packets"]
    ip_packets     = data["ip_packets"]

    psa = np.array(packet_sizes, dtype=np.float64)          # packet sizes array
    fsa = np.array(list(flows.values()), dtype=np.float64)  # flow sizes array
    total_tcp_udp = protocol_count["TCP"] + protocol_count["UDP"]

    print("\n" + "=" * 45)
    print("  TRAFFIC ANALYSIS STATISTICS")
    print("=" * 45)

    print(f"\n[Packets]")
    print(f"  Total:      {total_packets:>10,}")
    print(f"  IP:         {ip_packets:>10,}")
    print(f"  TCP:        {protocol_count['TCP']:>10,}  ({100*protocol_count['TCP']/total_tcp_udp:.1f}%)")
    print(f"  UDP:        {protocol_count['UDP']:>10,}  ({100*protocol_count['UDP']/total_tcp_udp:.1f}%)")

    print(f"\n[Packet Size (bytes)]")
    print(f"  Min: {psa.min():.0f}  Max: {psa.max():.0f}  Mean: {psa.mean():.2f}  "
          f"Median: {np.median(psa):.0f}  P95: {np.percentile(psa,95):.0f}")

    print(f"\n[Flows]")
    print(f"  Count:      {len(fsa):>10,}")

    print(f"\n[Flow Size (bytes)]")
    print(f"  Min: {fsa.min():.0f}  Max: {fsa.max():.0f}  Mean: {fsa.mean():.2f}  "
          f"Median: {np.median(fsa):.0f}  P95: {np.percentile(fsa,95):.0f}")

    mice     = int(np.sum(fsa < MICE_ELEPHANT_THRESHOLD))
    elephant = int(np.sum(fsa >= MICE_ELEPHANT_THRESHOLD))
    print(f"\n[Mice/Elephant (threshold 100 KB)]")
    print(f"  Mice:     {mice}  ({100*mice/len(fsa):.1f}%)")
    print(f"  Elephant: {elephant}  ({100*elephant/len(fsa):.1f}%)")

    return dict(
        psa=psa,
        fsa=fsa,
        mice=mice,
        elephant=elephant,
    )
