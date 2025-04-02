# capture_module.py
import pcapy  # Или Npcaplib для Windows, в зависимости от выбранной библиотеки
import socket
import struct
import threading
import time

class CaptureModule:
    def __init__(self):
        self.capture_thread = None
        self.running = False
        self.packet_queue = []  # Или используйте multiprocessing.Queue для потокобезопасности
        self.interface = None
        self.bpf_filter = ""
        self.pcap = None

    def get_interfaces(self):
        try:
            interfaces = pcapy.findalldevs() # Или используйте соответствующий вызов для Npcaplib
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []

    def start_capture(self, interface, bpf_filter=""):
        if self.running:
            print("Capture already running")
            return False

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = True
        self.packet_queue = [] # Очищаем очередь при перезапуске
        try:
            self.pcap = pcapy.open_live(self.interface, 65536, 1, 0) #  Попробуйте 1024 или 1500 для MTU
            self.pcap.setfilter(self.bpf_filter)
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            return True
        except Exception as e:
            print(f"Error starting capture: {e}")
            self.running = False
            return False

    def _capture_packets(self):
        while self.running:
            try:
                (header, packet) = self.pcap.next()
                self.packet_queue.append((header, packet)) # или используйте put() для Queue
            except pcapy.PcapError as e:
                if "Bad file descriptor" in str(e): #  Обработка закрытия сокета при остановке
                    break
                print(f"Capture error: {e}")
                break
            except Exception as e:
                print(f"Unexpected capture error: {e}")
                break
            # time.sleep(0.001)  #  Опционально: небольшая задержка для уменьшения нагрузки на процессор

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2) #  Ждем завершения потока
            self.capture_thread = None
        if self.pcap:
             try:
                self.pcap.close() #  Закрываем соединение.  Может быть нужно использовать другой метод для Npcaplib
             except Exception as e:
                 print(f"Error closing pcap: {e}")
        self.pcap = None


    def get_packets(self):
        # Возвращает копию очереди, чтобы избежать проблем с многопоточностью
        packets = self.packet_queue[:]
        self.packet_queue = [] #  Очищаем очередь после получения пакетов
        return packets