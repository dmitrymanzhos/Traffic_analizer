from collections import defaultdict
import time
from datetime import datetime
from typing import Dict, Any, DefaultDict
from loguru import logger

class StatisticsModule:
    def __init__(self):
        self.reset_statistics()
        self.traffic_history = {'timestamps': [], 'bytes': [], 'packets': []}

    def reset_statistics(self) -> None:
        """Reset all statistics counters"""
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.start_time: float = time.time()
        self.protocol_counts: DefaultDict[str, int] = defaultdict(int)
        self.ip_counts: DefaultDict[str, Dict[str, int]] = defaultdict(lambda: {'in': 0, 'out': 0})
        self.port_counts: DefaultDict[int, Dict[str, int]] = defaultdict(lambda: {'in': 0, 'out': 0})
        self.application_counts: DefaultDict[str, int] = defaultdict(int)
        self.stream_statistics: Dict[str, Dict[str, Any]] = {}
        logger.info("Statistics reset")

    def update_statistics(self, packet_info: Dict[str, Any]) -> None:
        """Update statistics with new packet info"""
        if not packet_info:
            return

        try:
            self.packet_count += 1
            payload_len = len(packet_info.get('payload', b''))
            self.byte_count += payload_len

            current_time = time.time() - self.start_time
            self.traffic_history['timestamps'].append(current_time)
            self.traffic_history['bytes'].append(self.byte_count)
            self.traffic_history['packets'].append(self.packet_count)
            
            # Protocol statistics
            protocol = packet_info.get('protocol', 'unknown')
            self.protocol_counts[protocol] += 1

            # IP direction statistics
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            if src_ip and dst_ip:
                self.ip_counts[src_ip]['out'] += 1
                self.ip_counts[dst_ip]['in'] += 1

            # Port statistics
            if 'src_port' in packet_info and 'dst_port' in packet_info:
                self.port_counts[packet_info['src_port']]['out'] += 1
                self.port_counts[packet_info['dst_port']]['in'] += 1

            # Application detection
            if packet_info.get('http_info'):
                self.application_counts['HTTP'] += 1
            elif protocol == 'DNS':
                self.application_counts['DNS'] += 1

            # TCP stream tracking
            if protocol == 'TCP' and 'stream_key' in packet_info:
                stream_key = packet_info['stream_key']
                if stream_key not in self.stream_statistics:
                    self.stream_statistics[stream_key] = {
                        'start_time': datetime.now(),
                        'packet_count': 0,
                        'byte_count': 0,
                        'src': f"{src_ip}:{packet_info.get('src_port', '')}",
                        'dst': f"{dst_ip}:{packet_info.get('dst_port', '')}"
                    }
                self.stream_statistics[stream_key]['packet_count'] += 1
                self.stream_statistics[stream_key]['byte_count'] += payload_len

        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Return current statistics snapshot"""
        return {
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'duration_sec': round(time.time() - self.start_time, 2),
            'protocol_counts': dict(self.protocol_counts),
            'ip_counts': dict(self.ip_counts),
            'port_counts': dict(self.port_counts),
            'application_counts': dict(self.application_counts),
            'stream_statistics': self.stream_statistics
        }

    def generate_report(self) -> str:
        """Generate HTML report with current statistics"""
        stats = self.get_statistics()
        report = [
            "<html><body>",
            "<h1>Network Traffic Analysis Report</h1>",
            f"<p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"<p>Capture duration: {stats['duration_sec']} seconds</p>",
            
            "<h2>Summary</h2>",
            f"<p>Total packets: {stats['packet_count']}</p>",
            f"<p>Total bytes: {stats['byte_count']}</p>",
            f"<p>Average packets/sec: {round(stats['packet_count']/max(1, stats['duration_sec']))}</p>",
            
            "<h2>Protocol Distribution</h2>",
            "<table border='1'><tr><th>Protocol</th><th>Count</th></tr>"
        ]
        
        for proto, count in stats['protocol_counts'].items():
            report.append(f"<tr><td>{proto}</td><td>{count}</td></tr>")
        
        report.extend([
            "</table>",
            "</body></html>"
        ])
        
        return "\n".join(report)

    def get_protocol_distribution(self):
        # Добавьте тестовые данные для проверки
        # return {'TCP': 15, 'UDP': 5, 'ICMP': 3} if not self.protocol_counts else dict(self.protocol_counts)
        return dict(self.protocol_counts)

    def get_traffic_timeline(self):
        """Возвращает временную шкалу трафика с инкрементальными значениями"""
        if len(self.traffic_history['timestamps']) < 2:
            return {'timestamps': [], 'bytes': [], 'packets': []}

        # Вычисляем разницу между соседними значениями
        bytes_diff = [self.traffic_history['bytes'][i] - self.traffic_history['bytes'][i-1] 
                    for i in range(1, len(self.traffic_history['bytes']))]
        packets_diff = [self.traffic_history['packets'][i] - self.traffic_history['packets'][i-1] 
                    for i in range(1, len(self.traffic_history['packets']))]
        timestamps = self.traffic_history['timestamps'][1:]

        return {
            'timestamps': timestamps,
            'bytes': bytes_diff,
            'packets': packets_diff
        }