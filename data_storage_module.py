# data_storage_module.py
import pcapy # или Npcaplib для Windows
import dpkt
import os
from datetime import datetime

class DataStorageModule:
    def __init__(self):
        pass

    def save_to_pcap(self, packet_data, filename):
        try:
            if not os.path.exists(filename): #  Создаем pcap файл, если его нет
                pcap = pcapy.open_offline(filename) #  Можно использовать open_live с интерфейсом "any" для записи
                pcap.close()

            with open(filename, 'ab') as f: #  Открываем в режиме добавления
                f.write(packet_data[1]) #  Записываем сырые данные пакета (packet_data[1])
        except Exception as e:
            print(f"Error saving to pcap: {e}")

    def load_from_pcap(self, filename):
        packets = []
        try:
            with open(filename, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    packets.append((ts, buf))
        except Exception as e:
            print(f"Error loading from pcap: {e}")
        return packets

    def save_stream(self, stream_data, filename):
        try:
            with open(filename, 'w') as f:
                f.write(stream_data['data'].decode('utf-8', 'ignore'))  # Сохраняем текст, игнорируем ошибки декодирования
        except Exception as e:
            print(f"Error saving stream: {e}")

    def save_statistics(self, statistics_data, filename):
        try:
            with open(filename, 'w') as f:
                # Форматируем статистику в удобный формат (например, CSV)
                f.write("Statistic,Value\n")
                for key, value in statistics_data.items():
                    f.write(f"{key},{value}\n")
        except Exception as e:
            print(f"Error saving statistics: {e}")