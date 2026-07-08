"""
utils.py
--------
Small helper functions shared across the project:
  - ip_to_str  : convert raw IP bytes to a readable string
  - open_pcap  : locate and open the pcap file (plain or inside tar.gz)
  - save_fig   : save the current matplotlib figure to disk
"""

import os
import socket
import tarfile

import matplotlib.pyplot as plt

from config import TAR_PATH, PCAP_PATH


def ip_to_str(address):
    """Convert raw IP address bytes into a human-readable string."""
    try:
        return socket.inet_ntoa(address)
    except Exception:
        return "unknown"


def open_pcap():
    """
    Return a file object for the PCAP data (auto-detects a plain .pcap
    file or one packed inside a .tar.gz archive).

    Returns:
        (file_object, tar_object_or_None)
        tar_object is returned so the caller can close it afterward
        if the pcap came from inside a tar archive.
    """
    if os.path.exists(PCAP_PATH):
        print(f"✔ Reading from: {PCAP_PATH}")
        return open(PCAP_PATH, "rb"), None

    if os.path.exists(TAR_PATH):
        print(f"✔ Extracting and reading from: {TAR_PATH}")
        tar = tarfile.open(TAR_PATH, "r:gz")
        for member in tar.getmembers():
            if member.name.endswith(".pcap"):
                return tar.extractfile(member), tar
        tar.close()
        raise FileNotFoundError("No .pcap file found inside the tar.gz!")

    raise FileNotFoundError(f"Neither '{PCAP_PATH}' nor '{TAR_PATH}' was found.")


def save_fig(filename):
    """Tighten layout, save the current figure to `filename`, and close it."""
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()
    print(f"  -> Saved: {filename}")
