from scapy.all import IP, IPv6, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest

import socket
from collections import defaultdict
from loguru import logger
from typing import Dict, Optional, Union
from scapy.packet import Packet

class PacketProcessingModule:
    def __init__(self):
        self.tcp_streams = defaultdict(lambda: {
            'data': b'',
            'packets': 0,
            'start_time': None,
            'last_activity': None
        })

    def process_packet(self, packet: Packet):
        """Process raw network packet and extract key information"""
        try:
            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                return None

            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            protocol = ip_layer.proto
            
            if not hasattr(ip_layer, 'proto'):
                return None

            # Base packet info
            packet_info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'version': 4 if packet.haslayer(IP) else 6,
                'timestamp': packet.time,
                'length': len(packet),
                'dns_query': '',  # для DNS
                'http_host': ''   # для HTTP
            }

            # DNS-запросы (UDP)
            if protocol == socket.IPPROTO_UDP and packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns = packet[DNS]
                if dns.qr == 0:  # QR=0 означает запрос
                    packet_info['dns_query'] = dns[DNSQR].qname.decode('utf-8', errors='ignore')

            # HTTP-запросы (TCP)
            if protocol == socket.IPPROTO_TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.payload:
                    raw_payload = bytes(tcp.payload)
                    try:
                        if b'Host: ' in raw_payload:  # HTTP-заголовок
                            http_header = raw_payload.split(b'\r\n')
                            for header in http_header:
                                if header.startswith(b'Host: '):
                                    packet_info['http_host'] = header[6:].decode('utf-8').strip()
                                    break
                    except UnicodeDecodeError:
                        pass
                        
            # TCP processing
            if protocol == socket.IPPROTO_TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.payload:
                    raw_payload = bytes(tcp.payload)
                    try:
                        if b'Host: ' in raw_payload:  # HTTP-заголовок
                            http_header = raw_payload.split(b'\r\n')
                            for header in http_header:
                                if header.startswith(b'Host: '):
                                    packet_info['http_host'] = header[6:].decode('utf-8').strip()
                                    break
                    except UnicodeDecodeError:
                        pass
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': tcp.flags,
                    'payload': bytes(tcp.payload) if tcp.payload else b'',
                    'stream_key': f"{ip_layer.src}:{tcp.sport}-{ip_layer.dst}:{tcp.dport}"
                })
                self._update_tcp_stream(packet_info)

            # UDP processing
            elif protocol == socket.IPPROTO_UDP and packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'payload': bytes(udp.payload) if udp.payload else b''
                })

            else:
                return None

            return packet_info

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None

    def _update_tcp_stream(self, packet_info: Dict) -> None:
        """Update TCP stream tracking information"""
        stream_key = packet_info['stream_key']
        stream = self.tcp_streams[stream_key]
        
        if stream['packets'] == 0:
            stream['start_time'] = packet_info['timestamp']
        
        stream['packets'] += 1
        stream['last_activity'] = packet_info['timestamp']
        stream['data'] += packet_info.get('payload', b'')