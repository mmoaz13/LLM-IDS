"""Generates one sample .pcap file per traffic scenario into samples/, so
there are ready-made files to try in the dashboard's Upload PCAP tab without
needing live network capture. The dashboard's own "Simulate Attacks" tab
generates these on the fly instead — this script is for grabbing standalone
files (e.g. to keep in the repo, or to open in Wireshark).

Run:
    python simulator/generate_samples.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import wrpcap

from simulator.traffic_generator import SCENARIOS

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def main():
    SAMPLES_DIR.mkdir(exist_ok=True)
    for key, scenario in SCENARIOS.items():
        packets = scenario["generator"]()
        out_path = SAMPLES_DIR / f"{key}.pcap"
        wrpcap(str(out_path), packets)
        print(f"{scenario['label']}: wrote {len(packets)} packets -> {out_path}")


if __name__ == "__main__":
    main()
