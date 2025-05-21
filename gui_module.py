import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                            QLabel, QPushButton, QLineEdit, QComboBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QFileDialog, QMessageBox, QSplitter, QTabWidget)
from PyQt5.QtCore import Qt, QTimer
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from loguru import logger
from typing import List
import time

class GuiModule(QWidget):
    def __init__(self, capture_module, packet_processing_module, 
                data_storage_module, statistics_module, main_module):
        super().__init__()
        self.capture_module = capture_module
        self.packet_processing_module = packet_processing_module
        self.data_storage_module = data_storage_module
        self.statistics_module = statistics_module
        self.main_module = main_module
        
        self.packets: List = []
        self.init_ui()
        self.setup_connections()
        
        self.packet_table.setSortingEnabled(True)
        self.packet_table.verticalHeader().setDefaultSectionSize(20)
        
        self.timer = QTimer(self)
        self.timer.setSingleShot(False)
        self.timer.timeout.connect(self.update_packet_list)
        self.timer.start(1000)

    def init_ui(self):
        self.setWindowTitle('Network Traffic Analyzer')
        self.setMinimumSize(1200, 800)
        
        # Главный layout
        layout = QVBoxLayout()
        
        # Панель управления
        self.setup_control_panel(layout)
        
        # Создаем виджет с вкладками
        self.tab_widget = QTabWidget()
        
        # Вкладка с пакетами
        self.packet_table = self.create_packet_table()
        self.tab_widget.addTab(self.packet_table, "Packets")
        
        # Вкладка с TCP потоками
        self.streams_table = self.create_streams_table()
        self.tab_widget.addTab(self.streams_table, "TCP Streams")
        
        layout.addWidget(self.tab_widget)
        
        # Графики
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        self.setLayout(layout)
        self.setup_plots()

    def setup_control_panel(self, layout):
        """Настройка панели управления"""
        control_panel = QHBoxLayout()
        
        # Элементы управления (как в вашем исходном коде)
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80")
        
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.save_btn = QPushButton("Save PCAP Now")
        self.stop_btn.setEnabled(False)
        
        control_panel.addWidget(QLabel("Interface:"))
        control_panel.addWidget(self.interface_combo)
        control_panel.addWidget(QLabel("BPF Filter:"))
        control_panel.addWidget(self.filter_edit)
        control_panel.addWidget(self.start_btn)
        control_panel.addWidget(self.stop_btn)
        control_panel.addWidget(self.save_btn)
        
        layout.addLayout(control_panel)

    def create_packet_table(self):
        """Создаем таблицу пакетов"""
        table = QTableWidget()
        table.setColumnCount(9)
        table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Dest IP", "Protocol", 
            "Src Port", "Dst Port", "Length", "Info", "TCP flags"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setDefaultSectionSize(20)
        return table

    def create_streams_table(self):
        """Создаем таблицу TCP потоков"""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            'ID', 'Source', 'Destination', 
            'State', 'Packets', 'Bytes', 'Duration'
        ])
        table.setSortingEnabled(True)
        return table

    def update_all(self):
        """Обновляем все элементы интерфейса"""
        self.update_packet_list()
        self.update_streams_display()
        self.update_statistics()
        self.update_plots()

    def setup_connections(self):
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_current_session)
        # self.save_pcap_btn.clicked.connect(self.save_to_pcap)
        # self.export_stats_btn.clicked.connect(self.export_stats)

    def refresh_interfaces(self):
        self.interface_combo.clear()
        try:
            interfaces = self.capture_module.get_interfaces()
            if not interfaces:
                QMessageBox.warning(self, "Warning", "No active interfaces found")
            self.interface_combo.addItems(interfaces)
        except Exception as e:
            logger.error(f"Interface refresh failed: {e}")
            QMessageBox.critical(self, "Error", f"Failed to get interfaces: {str(e)}")

    # def start_capture(self):
        # iface = self.interface_combo.currentText()
        # bpf_filter = self.filter_edit.text()
        
        # if not iface:
        #     QMessageBox.warning(self, "Error", "Select network interface!")
        #     return
            
        # if self.capture_module.start_capture(iface, bpf_filter):
        #     self.start_btn.setEnabled(False)
        #     self.stop_btn.setEnabled(True)
        #     logger.info(f"Capture started on {iface} with filter: {bpf_filter}")
        # else:
        #     QMessageBox.critical(self, "Error", "Failed to start capture!")

    def start_capture(self):
        try:
            iface = self.interface_combo.currentText()
            if not iface:
                QMessageBox.warning(self, "Error", "Select network interface!")
                return False
                
            if self.capture_module.start_capture(iface, self.filter_edit.text()):
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                return True
            return False
        except Exception as e:
            logger.error(f"Start capture error: {e}")
            return False
        def stop_capture(self):
            self.capture_module.stop_capture()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            logger.info("Capture stopped")

    def stop_capture(self):
        """Остановка захвата трафика"""
        try:
            if hasattr(self, 'capture_module'):
                self.capture_module.stop_capture()
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                logger.info("GUI: Capture stopped")
        except Exception as e:
            logger.error(f"GUI stop capture error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to stop capture: {str(e)}")
            
    def update_packet_list(self):
        try:
            new_packets = self.capture_module.get_packets()
            if not new_packets:
                return

            self.packet_table.setSortingEnabled(False)
            self.packet_table.setUpdatesEnabled(False)
            current_row_count = self.packet_table.rowCount()
            self.packet_table.setRowCount(current_row_count + len(new_packets))

            for i, packet in enumerate(new_packets, current_row_count):
                packet_info = self.packet_processing_module.process_packet(packet)
                if not packet_info:
                    continue
                self.statistics_module.update_statistics(packet_info)

                info_text = ""
                if packet_info.get('http_host'):
                    info_text = f"HTTP: {packet_info['http_host']}"
                elif packet_info.get('https_host'):
                    info_text = f"HTTPS: {packet_info['tls_sni']}"
                elif packet_info.get('dns_query'):
                    info_text = f"DNS: {packet_info['dns_query']}"
                # elif packet_info.get('protocol') == 'TCP':
                #     info_text = "TCP"  # Общая информация для TCP, если нет HTTP
                elif packet_info.get('protocol'):
                    info_text = packet_info['protocol']
                

                info_flags = ""
                _flags = {
                    'F': 'FIN',
                    'S': 'SYN',
                    'R': 'RST',
                    'P': 'PSH',
                    'A': 'ACK',
                    'U': 'URG',
                    'E': 'ECE',
                    'C': 'CWR',
                }
                if packet_info.get('protocol') == 'TCP':
                    # info_flags = str(packet_info['flags'])
                    # if packet_info['flags'] == 0x01:
                    #     info_flags =
                    info_flags = " ".join([_flags[i] for i in list(str(packet_info['flags']))])
                else:
                    pass


                items = [
                    datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f'),
                    packet_info.get('src_ip', ''),
                    packet_info.get('dst_ip', ''),
                    packet_info.get('protocol', ''),
                    str(packet_info.get('src_port', '')),
                    str(packet_info.get('dst_port', '')),
                    str(packet_info.get('length', '')),
                    info_text,
                    info_flags
                ]
                
                for col, text in enumerate(items):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.packet_table.setItem(i, col, item)

            self.packet_table.setUpdatesEnabled(True)
            self.packet_table.setSortingEnabled(True)
            # self.update_statistics()
            self.update_streams_display() 
            self.update_plots()
            
        except Exception as e:
            logger.error(f"Packet update error: {e}")

    # def update_statistics(self):
    #     stats = self.statistics_module.get_statistics()
    #     text = (
    #         f"<b>Packets:</b> {stats['packet_count']}<br>"
    #         f"<b>Bytes:</b> {stats['byte_count']}<br>"
    #         "<b>Protocols:</b><br>"
    #     )
    #     for proto, count in stats['protocol_counts'].items():
    #         text += f"  {proto}: {count}<br>"
    #     self.stats_text.setText(text)

    # def update_plots(self):
    #     stats = self.statistics_module.get_statistics()
    #     self.figure.clear()
    #     ax = self.figure.add_subplot(111)
        
    #     if stats['protocol_counts']:
    #         ax.bar(stats['protocol_counts'].keys(), 
    #               stats['protocol_counts'].values())
    #         ax.set_title("Traffic by Protocol")
    #         self.canvas.draw()


    def setup_plots(self):
        """Инициализация области с графиками"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.text(0.5, 0.5, 'Графики будут здесь', 
            ha='center', va='center')
        self.canvas.draw()
        # self.plot_widget = QWidget()
        # self.plot_layout = QVBoxLayout(self.plot_widget)
        
        # # График распределения протоколов
        # self.protocol_fig = Figure(figsize=(5, 3))
        # self.protocol_pie = FigureCanvas(self.protocol_fig)
        # self.plot_layout.addWidget(self.protocol_pie)
        
        # # График временной шкалы трафика
        # self.traffic_fig = Figure(figsize=(8, 3))
        # self.traffic_plot = FigureCanvas(self.traffic_fig)
        # self.plot_layout.addWidget(self.traffic_plot)
        
        # # self.layout().insertLayout(3, self.plot_layout)  # Добавляем после таблицы
        # plot_container = QWidget()
        # plot_container.setLayout(self.plot_layout)
        # self.layout().insertWidget(3, plot_container)

    def update_plots(self):
        try:
            self.figure.clear()
            
            # Данные для графиков
            protocol_data = self.statistics_module.get_protocol_distribution()
            traffic_data = self.statistics_module.get_traffic_timeline()
            
            if not protocol_data or not traffic_data:
                ax = self.figure.add_subplot(111)
                ax.text(0.5, 0.5, 'Нет данных для отображения', ha='center', va='center')
                self.canvas.draw()
                return

            # График 1: Распределение протоколов
            ax1 = self.figure.add_subplot(121)
            if protocol_data:
                ax1.pie(
                    protocol_data.values(),
                    labels=protocol_data.keys(),
                    autopct='%1.1f%%',
                    startangle=90
                )
                ax1.set_title("Protocol Distribution")

            # График 2: Трафик по времени
            ax2 = self.figure.add_subplot(122)
            if traffic_data['timestamps']:
                ax2.plot(
                    traffic_data['timestamps'],
                    traffic_data['bytes'],
                    'b-', label='Bytes'
                )
                ax2.set_xlabel('Time (sec)')
                ax2.set_ylabel('Bytes per interval')
                ax2.set_title("Traffic Over Time")
                ax2.legend(loc='upper left')
                ax2.grid(True)

            self.figure.tight_layout()  # Чтобы графики не накладывались
            self.canvas.draw()

        except Exception as e:
            logger.error(f"Ошибка при обновлении графиков: {e}")
                
    def update_protocol_pie(self):
        """Обновление круговой диаграммы протоколов"""
        stats = self.statistics_module.get_protocol_distribution()
        if not stats or len(stats) < 1:
            return
        
        self.protocol_fig.clear()
        ax = self.protocol_fig.add_subplot(111)
        
        ax.pie(stats.values(), labels=stats.keys(), autopct='%1.1f%%')
        ax.set_title("Protocol Distribution")
        self.protocol_pie.draw()

    def update_traffic_plot(self):
        """Обновление графика трафика"""
        timeline = self.statistics_module.get_traffic_timeline()
        if not timeline['timestamps']:
            return
        
        fig = self.traffic_plot.figure
        fig.clear()
        ax = fig.add_subplot(111)
        
        ax.plot(timeline['timestamps'], timeline['bytes'], label='Bytes')
        ax.plot(timeline['timestamps'], timeline['packets'], label='Packets')
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Count')
        ax.set_title("Traffic Timeline")
        ax.legend()
        ax.grid(True)
        
        self.traffic_plot.draw()

    def update_streams_display(self):
        try:
            streams = self.packet_processing_module.get_active_streams()
            self.streams_table.setRowCount(len(streams))
            
            for row, (stream_id, data) in enumerate(streams.items()):
                # Проверка наличия необходимых данных
                if not all(key in data for key in ['start_time', 'end_time', 'src_ip', 'dst_ip']):
                    continue
                    
                duration = data['end_time'] - data['start_time']
                packets_count = len(data.get('packets', []))
                bytes_count = sum(p.get('length', 0) for p in data.get('packets', []))
                
                items = [
                    stream_id[:15],
                    f"{data['src_ip']}:{data.get('src_port', '')}",
                    f"{data['dst_ip']}:{data.get('dst_port', '')}",
                    data.get('state', 'UNKNOWN'),
                    str(packets_count),
                    str(bytes_count),
                    f"{duration:.2f}s",
                    str(data.get('retransmissions', 0))
                ]
                
                for col, text in enumerate(items):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self._set_stream_state_color(item, data.get('state'))
                    self.streams_table.setItem(row, col, item)
                    
        except Exception as e:
            logger.error(f"Error updating streams table: {e}")

    def _set_stream_state_color(self, item, state):
        """Установка цвета фона в зависимости от состояния потока"""
        if state == 'ESTABLISHED':
            item.setBackground(Qt.green)
        elif state in ('CLOSING', 'TIMEOUT'):
            item.setBackground(Qt.yellow)
        elif state == 'ABORTED':
            item.setBackground(Qt.red)
        
    def save_current_session(self):
        """Ручное сохранение текущих пакетов"""
        packets = self.capture_module.get_all_packets()
        if packets:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save PCAP", "", "PCAP Files (*.pcap)")
            if filename:
                if self.data_storage_module.save_to_pcap(packets, filename):
                    QMessageBox.information(self, "Success", 
                        f"Saved {len(packets)} packets")
        else:
            QMessageBox.warning(self, "Warning", "No packets to save")


    # def create_streams_table(self):
    #     """Создаем таблицу для отображения TCP-потоков"""
    #     table = QTableWidget()
    #     table.setColumnCount(7)
    #     table.setHorizontalHeaderLabels([
    #         'ID', 'Source', 'Destination', 
    #         'State', 'Packets', 'Bytes', 'Duration'
    #     ])
    #     return table
        


    # def save_to_pcap(self):
    #     filename, _ = QFileDialog.getSaveFileName(
    #         self, "Save PCAP", "", "PCAP Files (*.pcap)")
            
    #     if filename:
    #         packets = [p for p in self.packets if p[1]]
    #         if packets:
    #             success = self.data_storage_module.save_to_pcap(packets, filename)
    #             if success:
    #                 QMessageBox.information(self, "Success", f"Saved {len(packets)} packets")
    #             else:
    #                 QMessageBox.warning(self, "Error", "Failed to save packets")
    #         else:
    #             QMessageBox.warning(self, "Error", "No packets to save!")

    # def export_stats(self):
    #     filename, _ = QFileDialog.getSaveFileName(
    #         self, "Export Stats", "", "CSV (*.csv)")
            
    #     if filename:
    #         try:
    #             stats = self.statistics_module.get_statistics()
    #             with open(filename, 'w') as f:
    #                 f.write("Category,Value\n")
    #                 f.write(f"Total Packets,{stats['packet_count']}\n")
    #                 for proto, count in stats['protocol_counts'].items():
    #                     f.write(f"{proto} Packets,{count}\n")
    #             QMessageBox.information(self, "Success", "Statistics exported")
    #         except Exception as e:
    #             QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")

    def closeEvent(self, event):
        if hasattr(self, 'capture_module') and self.capture_module.running:
            reply = QMessageBox.question(
                self, 'Confirm Exit',
                'Capture is running. Are you sure you want to exit?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.No:
                event.ignore()
                return
                
        if hasattr(self, 'timer'):
            self.timer.stop()
        if hasattr(self, 'main_module'):
            self.main_module.stop()
        event.accept()

    # def showEvent(self, event):
    #     # Временно для теста
    #     self.update_protocol_pie()
    #     self.update_traffic_plot()
    #     super().showEvent(event)