from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception
import threading
import queue
from loguru import logger

class CaptureModule:
    def __init__(self):
        self.capture_thread = None
        self.running = False
        self.packet_queue = queue.Queue()
        self.interface = None
        self.bpf_filter = ""

    def get_interfaces(self):
        """Получение списка сетевых интерфейсов"""
        try:
            interfaces = get_if_list()
            return [iface for iface in interfaces if iface != "lo"]
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []

    def start_capture(self, interface, bpf_filter=""):
        if self.running:
            logger.warning("Capture already running")
            return False

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = True

        try:
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                daemon=True
            )
            self.capture_thread.start()
            return True
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            self.running = False
            return False

    def _capture_packets(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda pkt: self.packet_queue.put(pkt),
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Scapy error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)

    def get_packets(self):
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        return packets