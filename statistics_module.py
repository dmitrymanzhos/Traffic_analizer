# statistics_module.py
from collections import defaultdict
import time
from datetime import datetime

class StatisticsModule:
    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts = defaultdict(int)
        self.ip_counts = defaultdict(lambda: {'in':0, 'out':0})  #  Разделение входящего и исходящего трафика
        self.port_counts = defaultdict(lambda: {'in':0, 'out':0}) #  Разделение входящего и исходящего трафика
        self.application_counts = defaultdict(int)
        self.stream_statistics = {}

    def update_statistics(self, packet_info):
        self.packet_count += 1
        if packet_info:
            self.byte_count += len(packet_info.get('payload', b'')) # Учитываем размер полезной нагрузки
            self.protocol_counts[packet_info['protocol']] += 1

            #  Учитываем входящий/исходящий трафик
            self.ip_counts[packet_info['src_ip']]['out'] += 1
            self.ip_counts[packet_info['dst_ip']]['in'] += 1

            if 'src_port' in packet_info and 'dst_port' in packet_info:
                self.port_counts[packet_info['src_port']]['out'] += 1
                self.port_counts[packet_info['dst_port']]['in'] += 1

            if 'http_info' in packet_info and packet_info['http_info']:
                self.application_counts['HTTP'] +=1 #  Simple DPI (можно улучшить)

            if packet_info.get('protocol') == 'TCP' and 'stream_key' in packet_info:
               stream_key = packet_info['stream_key']
               if stream_key not in self.stream_statistics:
                   self.stream_statistics[stream_key] = {
                       'start_time': datetime.now(),
                       'packet_count': 0,
                       'byte_count': 0
                    }
               self.stream_statistics[stream_key]['packet_count'] +=1
               self.stream_statistics[stream_key]['byte_count'] += len(packet_info.get('payload', b''))

    def get_statistics(self):
        return {
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'protocol_counts': dict(self.protocol_counts), #  Возвращаем копии для предотвращения изменений извне
            'ip_counts': dict(self.ip_counts),
            'port_counts': dict(self.port_counts),
            'application_counts': dict(self.application_counts),
            'stream_statistics': self.stream_statistics
        }

    def reset_statistics(self):
        self.__init__() #  Переинициализируем все счетчики

    def generate_report(self):
        #TODO:  Создание отчета (HTML, CSV, или другой формат)
        report = "<html><body>"
        report += f"<h1>Network Traffic Analysis Report</h1>"
        report += f"<p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"

        statistics = self.get_statistics()

        report += "<h2>General Statistics</h2>"
        report += f"<p>Packets captured: {statistics['packet_count']}</p>"
        report += f"<p>Bytes captured: {statistics['byte_count']}</p>"

        report += "<h2>Protocol Statistics</h2>"
        report += "<ul>"
        for protocol, count in statistics['protocol_counts'].items():
            report += f"<li>{protocol}: {count}</li>"
        report += "</ul>"

        report += "</body></html>"
        return report