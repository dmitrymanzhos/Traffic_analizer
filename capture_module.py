from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception
import threading
import queue
from loguru import logger

class CaptureModule:
    def __init__(self):
        self.capture_thread = None
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000) 
        self.interface = None
        self.bpf_filter = ""
        self.captured_packets = []

    def get_interfaces(self):
        """Возвращает список сетевых интерфейсов, исключая loopback"""
        try:
            return [iface for iface in get_if_list() if iface != "lo"]
        except Exception as e:
            logger.error(f"Interface list error: {e}")
            return []

    def start_capture(self, interface, bpf_filter=""):
        """Запускает асинхронный захват трафика"""
        if self.running:
            logger.warning("Capture already running")
            return False

        if not interface or interface not in self.get_interfaces():
            logger.error(f"Invalid interface: {interface}")
            return False

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = True

        try:
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                daemon=True,
                name="PacketCaptureThread"  # имя потока
            )
            self.capture_thread.start()
            logger.info(f"Capture started on {interface} (filter: {bpf_filter})")
            return True
        except Exception as e:
            logger.error(f"Capture start failed: {e}")
            self.running = False
            return False

    def _capture_packets(self):
        """Внутренний метод для захвата пакетов"""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda pkt: (
                    self.packet_queue.put(pkt, block=False),
                    self.captured_packets.append(pkt)
                ),
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Scapy error: {e}")
        except queue.Full:
            logger.warning("Packet queue full - packets may be dropped")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False

    def stop_capture(self):
        """Останавливает захват трафика"""
        if self.running:
            self.running = False
            if self.capture_thread:
                self.capture_thread.join(timeout=2)
            logger.info("Capture stopped")

    def get_packets(self):
        """Возвращает все пакеты из очереди"""
        packets = []
        while not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets
    
    def get_all_packets(self):
        """Возвращает все захваченные пакеты"""
        packets = list(self.captured_packets) 
        while not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                packets.append(packet)
                self.captured_packets.append(packet)
            except queue.Empty:
                break
        return packets