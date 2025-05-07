from scapy.all import IP, IPv6, TCP, UDP, Raw
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

    def process_packet(self, packet: Packet) -> Optional[Dict]:
        """Process raw network packet and extract key information"""
        try:
            # Basic protocol check
            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                return None

            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            protocol = ip_layer.proto
            
            # Base packet info
            packet_info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'version': 4 if packet.haslayer(IP) else 6,
                'timestamp': packet.time,
                'length': len(packet)
            }

            # TCP processing
            if protocol == socket.IPPROTO_TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
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