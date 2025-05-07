from scapy.all import wrpcap, rdpcap
import os
from loguru import logger

class DataStorageModule:
    def save_to_pcap(self, packets, filename):
        try:
            wrpcap(filename, packets, append=True)  # Автоматически создает файл
            logger.success(f"Saved {len(packets)} packets to {filename}")
        except Exception as e:
            logger.error(f"PCAP save error: {e}")

    def load_from_pcap(self, filename):
        try:
            return rdpcap(filename)
        except Exception as e:
            logger.error(f"PCAP load error: {e}")
            return []