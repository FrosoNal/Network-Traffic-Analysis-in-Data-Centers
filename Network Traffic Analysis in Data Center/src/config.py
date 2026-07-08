"""
config.py
---------
Global settings: input file paths and the color palette used in the plots.
"""

import matplotlib
matplotlib.use('Agg')   # headless backend — saves plots to files instead of showing them

# =========================
# SETTINGS
# =========================

TAR_PATH  = "trace.tar.gz"
PCAP_PATH = "trace.pcap"

BLUE   = "#2E75B6"
ORANGE = "#E07B39"
GREEN  = "#4CAF50"
