# Network Traffic Analysis in Data Centers

## Description
This project focuses on the analysis of network traffic captured in PCAP traces. The primary objective is to extract and visualize key traffic characteristics, including flow sizes and packet distributions, to identify patterns in data center network traffic.

## Methodology
- **Parsing:** The code uses the `dpkt` library to parse PCAP files (supporting both raw `.pcap` and compressed `.tar.gz` formats).
- **Flow Grouping:** Network traffic is grouped into flows based on the standard **5-tuple**:
    - Source/Destination IP Address 
    - Source/Destination Port 
    - Protocol (TCP or UDP) 
- **Metrics Extracted:**
    - Packet Size (bytes) 
    - Flow Size (bytes) 
- **Analysis:** Flows are categorized into "Mice" (< 100 KB) and "Elephant" (≥ 100 KB) flows to highlight traffic trends.

## Prerequisites
Ensure the required Python libraries are installed:
```bash
pip install dpkt matplotlib numpy
