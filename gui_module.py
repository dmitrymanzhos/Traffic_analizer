import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QLineEdit, QComboBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QTimer
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from loguru import logger

class GuiModule(QWidget):
    def __init__(self, capture_module, packet_processing_module, 
                 data_storage_module, statistics_module, main_module):
        super().__init__()
        # Инициализация модулей
        self.capture_module = capture_module
        self.packet_processing_module = packet_processing_module
        self.data_storage_module = data_storage_module
        self.statistics_module = statistics_module
        self.main_module = main_module
        
        # Настройка UI
        self.packets = []
        self.init_ui()
        
        # Таймер для обновления интерфейса
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_packet_list)
        self.timer.start(1000)  # Обновление каждую секунду

    def init_ui(self):
        self.setWindowTitle('Network Traffic Analyzer (Scapy)')
        self.setGeometry(100, 100, 1200, 800)

        # 1. Панель управления
        control_panel = QHBoxLayout()
        
        # Выбор интерфейса
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        
        # Фильтр BPF
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80")
        
        # Кнопки управления
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        
        control_panel.addWidget(QLabel("Interface:"))
        control_panel.addWidget(self.interface_combo)
        control_panel.addWidget(QLabel("BPF Filter:"))
        control_panel.addWidget(self.filter_edit)
        control_panel.addWidget(self.start_btn)
        control_panel.addWidget(self.stop_btn)

        # 2. Таблица пакетов
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        headers = ["Time", "Source IP", "Dest IP", "Protocol", 
                  "Src Port", "Dst Port", "Length", "Info"]
        self.packet_table.setHorizontalHeaderLabels(headers)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # 3. Панель статистики
        self.stats_label = QLabel("Statistics:")
        self.stats_text = QLabel("No data captured")
        self.stats_text.setWordWrap(True)

        # 4. Визуализация
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        
        # 5. Кнопки экспорта
        export_panel = QHBoxLayout()
        self.save_pcap_btn = QPushButton("Save PCAP")
        self.export_stats_btn = QPushButton("Export Stats")

        # Основной лейаут
        layout = QVBoxLayout()
        layout.addLayout(control_panel)
        layout.addWidget(self.packet_table)
        layout.addWidget(self.stats_label)
        layout.addWidget(self.stats_text)
        layout.addWidget(self.canvas)
        layout.addLayout(export_panel)
        self.setLayout(layout)

        # Сигналы
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_pcap_btn.clicked.connect(self.save_to_pcap)
        self.export_stats_btn.clicked.connect(self.export_stats)

    def refresh_interfaces(self):
        """Обновление списка сетевых интерфейсов"""
        self.interface_combo.clear()
        interfaces = self.capture_module.get_interfaces()
        if not interfaces:
            QMessageBox.warning(self, "Error", "No network interfaces found!")
        for iface in interfaces:
            self.interface_combo.addItem(iface)

    def start_capture(self):
        """Запуск захвата трафика"""
        iface = self.interface_combo.currentText()
        bpf_filter = self.filter_edit.text()
        
        if not iface:
            QMessageBox.warning(self, "Error", "Select network interface!")
            return
            
        if self.capture_module.start_capture(iface, bpf_filter):
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            logger.info(f"Capture started on {iface} with filter: {bpf_filter}")
        else:
            QMessageBox.critical(self, "Error", "Failed to start capture!")

    def stop_capture(self):
        """Остановка захвата"""
        self.capture_module.stop_capture()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        logger.info("Capture stopped")

    def update_packet_list(self):
        """Обновление таблицы пакетов"""
        new_packets = self.capture_module.get_packets()
        if not new_packets:
            return

        self.packet_table.setRowCount(0)
        
        for i, packet in enumerate(new_packets):
            packet_info = self.packet_processing_module.process_packet(packet)
            if not packet_info:
                continue
                
            # Добавление строки в таблицу
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            # Заполнение данных
            self.packet_table.setItem(row, 0, 
                QTableWidgetItem(datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')))
            
            for col, key in enumerate(["src_ip", "dst_ip", "protocol", 
                                     "src_port", "dst_port"], 1):
                self.packet_table.setItem(row, col, 
                    QTableWidgetItem(str(packet_info.get(key, ""))))
            
            self.packet_table.setItem(row, 6, 
                QTableWidgetItem(str(len(packet_info.get("payload", b"")))))
            
            # HTTP информация (если есть)
            http_info = ""
            if "http_info" in packet_info:
                http_info = f"HTTP {packet_info['http_info'].get('method', '')}"
            self.packet_table.setItem(row, 7, QTableWidgetItem(http_info))

        self.update_statistics()
        self.update_plots()

    def update_statistics(self):
        """Обновление статистики"""
        stats = self.statistics_module.get_statistics()
        text = (
            f"<b>Packets:</b> {stats['packet_count']}<br>"
            f"<b>Bytes:</b> {stats['byte_count']}<br>"
            "<b>Protocols:</b><br>"
        )
        for proto, count in stats['protocol_counts'].items():
            text += f"  {proto}: {count}<br>"
        self.stats_text.setText(text)

    def update_plots(self):
        """Обновление графиков"""
        stats = self.statistics_module.get_statistics()
        
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        if stats['protocol_counts']:
            ax.bar(stats['protocol_counts'].keys(), 
                  stats['protocol_counts'].values())
            ax.set_title("Traffic by Protocol")
            self.canvas.draw()

    def save_to_pcap(self):
        """Сохранение в PCAP"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "", "PCAP Files (*.pcap)")
            
        if filename:
            packets = [p for p in self.packets if p[1]]  # Отфильтровать None
            if packets:
                self.data_storage_module.save_to_pcap(packets, filename)
                QMessageBox.information(self, "Success", f"Saved {len(packets)} packets")
            else:
                QMessageBox.warning(self, "Error", "No packets to save!")

    def export_stats(self):
        """Экспорт статистики"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Stats", "", "CSV (*.csv)")
            
        if filename:
            try:
                stats = self.statistics_module.get_statistics()
                with open(filename, 'w') as f:
                    f.write("Category,Value\n")
                    f.write(f"Total Packets,{stats['packet_count']}\n")
                    for proto, count in stats['protocol_counts'].items():
                        f.write(f"{proto} Packets,{count}\n")
                QMessageBox.information(self, "Success", "Statistics exported")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")

    def closeEvent(self, event):
        """Обработка закрытия окна"""
        self.stop_capture()
        super().closeEvent(event)