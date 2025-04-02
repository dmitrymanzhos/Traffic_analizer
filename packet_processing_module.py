# packet_processing_module.py
import dpkt
import socket
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw  # Используем scapy для более удобного разбора
import ssl #  Для DPI/TLS
from datetime import datetime

class PacketProcessingModule:
    def __init__(self):
        self.tcp_streams = {}
        self.quic_streams = {}
        self.tls_keys = {}

    def process_packet(self, packet_data):
        try:
            eth = Ether(packet_data) # Используем scapy

            if 'IP' in eth:
                ip = eth['IP']
                src_ip = ip.src
                dst_ip = ip.dst
                proto = ip.proto
                version = 4
            elif 'IPv6' in eth:
                ip = eth['IPv6']
                src_ip = ip.src
                dst_ip = ip.dst
                proto = ip.nxt
                version = 6
            else:
                return None #  Не IP пакет

            if proto == socket.IPPROTO_TCP and 'TCP' in eth:
                tcp = eth['TCP']
                src_port = tcp.sport
                dst_port = tcp.dport
                payload = bytes(tcp.payload) if 'payload' in tcp else b""
                packet_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': 'TCP',
                    'version': version,
                    'payload': payload
                }
                return packet_info

            elif proto == socket.IPPROTO_UDP and 'UDP' in eth:
                udp = eth['UDP']
                src_port = udp.sport
                dst_port = udp.dport
                payload = bytes(udp.payload) if 'payload' in udp else b""
                packet_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': 'UDP',
                    'version': version,
                    'payload': payload
                }
                #TODO: Распознать QUIC тут (по порту, или по заголовку)
                return packet_info

        except Exception as e:
            print(f"Error processing packet: {e}")
            return None

    def reconstruct_tcp_stream(self, packet_info):
        if packet_info['protocol'] != 'TCP':
            return None

        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        src_port = packet_info['src_port']
        dst_port = packet_info['dst_port']
        payload = packet_info['payload']

        stream_key = ((src_ip, src_port), (dst_ip, dst_port)) #  Используем кортежи как ключи словаря
        stream_key_reversed = ((dst_ip, dst_port), (src_ip, src_port))

        if stream_key in self.tcp_streams:
            stream = self.tcp_streams[stream_key]
        elif stream_key_reversed in self.tcp_streams:
            stream = self.tcp_streams[stream_key_reversed]
        else:
            stream = {
                'data': b"",
                'start_time': datetime.now(),
                'packets': 0
            }
            self.tcp_streams[stream_key] = stream

        if payload:
            stream['data'] += payload
            stream['packets'] += 1

        return stream

    def extract_http_info(self, payload):
        try:
            #  Простая реализация HTTP парсинга (можно улучшить)
            if payload.startswith(b'GET') or payload.startswith(b'POST') or payload.startswith(b'HTTP'): #  Определяем начало HTTP запроса/ответа
                http_message = payload.split(b'\r\n\r\n', 1) #  Разделяем заголовки и тело
                headers = http_message[0].split(b'\r\n')
                method = headers[0].split(b' ')[0].decode('utf-8', 'ignore') #  GET, POST, ...
                #TODO:  Парсинг заголовков
                return {
                    'method': method,
                    'headers': [h.decode('utf-8', 'ignore') for h in headers]
                }
            return None
        except Exception as e:
            print(f"Error extracting HTTP info: {e}")
            return None

    def add_tls_key(self, pre_master_secret):
        #TODO: Реализация добавления ключей для расшифровки TLS
        #  Использовать библиотеку (например, pyOpenSSL) или логику обработки pre-master secret
        pass


    def reconstruct_quic_stream(self, packet_info):
        #TODO: Реализация реконструкции QUIC потоков
        return None