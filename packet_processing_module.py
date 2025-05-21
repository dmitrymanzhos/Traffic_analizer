from scapy.all import IP, IPv6, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
import socket
from collections import defaultdict
from loguru import logger
from typing import Dict, List
from scapy.packet import Packet
import time

class PacketProcessingModule:
    def __init__(self):
        self.tcp_streams = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'packets': [],          #  все пакеты потока
            'state': 'UNKNOWN',     # флаг остояния из UNKNOWN/NEW/SYN_SENT/ESTABLISHED/CLOSING/CLOSED/ABORTED
            'flags_history': [],     
            'src_ip': '',
            'dst_ip': '',
            'src_port': 0,
            'dst_port': 0
        })
        self.stream_timeout = 300

    def process_packet(self, packet: Packet):
        """Обработка пакета """
        try:
            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                return None

            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            protocol = ip_layer.proto
            
            packet_info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'version': 4 if packet.haslayer(IP) else 6,
                'timestamp': packet.time,
                'length': len(packet),
                'payload': b'',
                'dns_query': '',
                'http_host': '',
                'tls_sni': ''
            }

            # TCP
            if protocol == socket.IPPROTO_TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
                payload = bytes(tcp.payload) if tcp.payload else b''
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': tcp.flags,
                    'payload': payload,
                    'stream_key': self._generate_stream_key(ip_layer.src, tcp.sport, 
                                                         ip_layer.dst, tcp.dport),
                    'http_host': self._extract_http_host(payload),
                    'tls_sni': self._extract_tls_sni(payload)
                })
                self._update_tcp_stream(packet_info)
                
            # UDP 
            elif protocol == socket.IPPROTO_UDP and packet.haslayer(UDP):
                udp = packet[UDP]
                payload = bytes(udp.payload) if udp.payload else b''
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'payload': payload,
                    'dns_query': self._extract_dns_query(payload)
                })

            return packet_info

        except Exception as e:
            logger.error(f"Packet processing error: {e}")
            return None

    def _generate_stream_key(self, src_ip: str, src_port: int, 
                          dst_ip: str, dst_port: int) -> str:
        """Генерация ключа потока """
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        elif src_ip > dst_ip:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        else:
            return f"{min(src_port, dst_port)}-{max(src_port, dst_port)}"

    def _update_tcp_stream(self, packet_info: Dict) -> None:
        """Расширенный анализ состояния TCP-потока"""
        stream_key = packet_info['stream_key']
        stream = self.tcp_streams[stream_key]
        
        # Инициализация нового потока
        if not stream['packets']:
            self._init_new_stream(stream, packet_info)
        
        # Обновление данных потока
        stream['packets'].append(packet_info)
        stream['end_time'] = packet_info['timestamp']
        stream['flags_history'].append(packet_info['flags'])
        
        # Анализ флагов TCP
        self._analyze_tcp_flags(stream, packet_info['flags'])
        
        # Проверка таймаута
        if stream['state'] == 'ESTABLISHED':
            if packet_info['timestamp'] - stream['last_activity'] > self.stream_timeout:
                stream['state'] = 'TIMEOUT'
                logger.warning(f"Stream {stream_key} timed out")

    def _init_new_stream(self, stream: Dict, packet_info: Dict):
        """Инициализация нового TCP-потока"""
        stream.update({
            'start_time': packet_info['timestamp'],
            'end_time': packet_info['timestamp'],
            'last_activity': packet_info['timestamp'],
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'src_port': packet_info['src_port'],
            'dst_port': packet_info['dst_port'],
            'state': 'NEW',
            'packets': [],
            'flags_history': [],
            'retransmissions': 0
        })
    

    def _analyze_tcp_flags(self, stream: Dict, flags: int):
        """Определение состояния на основе TCP-флагов"""
        current_time = time.time()

        if flags & 0x02:  # SYN
            if stream['state'] == 'NEW':
                stream['state'] = 'SYN_SENT'
            elif stream['state'] in ['ESTABLISHED', 'CLOSING']:
                stream['retransmissions'] += 1
                
        elif flags & 0x10:  # ACK
            if stream['state'] == 'SYN_SENT':
                stream['state'] = 'ESTABLISHED'
            stream['last_activity'] = current_time
            
        elif flags & 0x01:  # FIN
            if stream['state'] == 'ESTABLISHED':
                stream['state'] = 'CLOSING'
            elif stream['state'] == 'CLOSING':
                stream['state'] = 'CLOSED'
                
        elif flags & 0x04:  # RST
            stream['state'] = 'ABORTED'

    def get_connection_issues(self):
        try:
            issues = defaultdict(list)
            for stream_id, stream in self.tcp_streams.items():
                if stream['retransmissions'] > 3:
                    issues['retransmissions'].append(stream_id)
                if stream['state'] == 'TIMEOUT':
                    issues['timeouts'].append(stream_id)
                if stream['state'] == 'ABORTED':
                    issues['aborted'].append(stream_id)
            return dict(issues)
        except Exception as e:
            logger.error(f"Get connection issues error: {e}")
            return {}
            
    def get_active_streams(self) -> Dict:
        """Возвращает активные потоки """
        return {k: v for k, v in self.tcp_streams.items() 
                if v['state'] not in ['CLOSED', 'UNKNOWN']}

    def get_stream_packets(self, stream_key: str) -> List[Dict]:
        """Возвращает все пакеты указанного потока"""
        return self.tcp_streams.get(stream_key, {}).get('packets', [])

    def _extract_http_host(self, payload: bytes) -> str:
        """Извлечение HTTP-хоста из сырых данных"""
        try:
            if b'Host:' in payload:
                host_line = payload.split(b'Host:')[1].split(b'\r\n')[0]
                return host_line.decode('utf-8').strip()
        except Exception:
            pass
        return ""

    def _extract_tls_sni(self, payload: bytes) -> str:
        """Извлечение SNI из TLS Client Hello"""
        try:
            if b'\x00\x00' in payload:  # TLS Client Hello marker
                sni_start = payload.find(b'\x00\x00') + 3
                sni_length = payload[sni_start-1]
                return payload[sni_start:sni_start+sni_length].decode('utf-8')
        except Exception:
            pass
        return ""

    def _extract_dns_query(self, payload: bytes) -> str:
        """Извлечение DNS-запроса"""
        try:
            if len(payload) > 12:  # Minimal DNS packet
                query = payload[12:].split(b'\x00')[0]
                return query.decode('utf-8')
        except Exception:
            pass
        return ""