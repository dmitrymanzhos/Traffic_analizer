from scapy.all import IP, IPv6, TCP, UDP, Raw
import socket
from collections import defaultdict

class PacketProcessingModule:
    def __init__(self):
        self.tcp_streams = defaultdict(lambda: {
            'data': b'',
            'packets': 0
        })

    def process_packet(self, packet):
        try:
            if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                return None

            ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            proto = ip.proto
            
            info = {
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'version': 4 if packet.haslayer(IP) else 6
            }

            if proto == socket.IPPROTO_TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
                info.update({
                    'protocol': 'TCP',
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'payload': bytes(tcp.payload) if tcp.payload else b''
                })
            elif proto == socket.IPPROTO_UDP and packet.haslayer(UDP):
                udp = packet[UDP]
                info.update({
                    'protocol': 'UDP',
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'payload': bytes(udp.payload) if udp.payload else b''
                })
            else:
                return None

            return info
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
            return None