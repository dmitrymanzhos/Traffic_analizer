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
from typing import List

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
        self.setMinimumSize(800, 600)
        
        # Control Panel
        self.control_panel = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80")
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        
        self.control_panel.addWidget(QLabel("Interface:"))
        self.control_panel.addWidget(self.interface_combo)
        self.control_panel.addWidget(QLabel("BPF Filter:"))
        self.control_panel.addWidget(self.filter_edit)
        self.control_panel.addWidget(self.start_btn)
        self.control_panel.addWidget(self.stop_btn)

        # Packet Table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        headers = ["Time", "Source IP", "Dest IP", "Protocol", 
                  "Src Port", "Dst Port", "Length", "Info"]
        self.packet_table.setHorizontalHeaderLabels(headers)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # Stats Panel
        self.stats_label = QLabel("Statistics:")
        self.stats_text = QLabel("No data captured")
        self.stats_text.setWordWrap(True)

        # Visualization
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        
        # Export Panel
        self.export_panel = QHBoxLayout()
        self.save_pcap_btn = QPushButton("Save PCAP")
        self.export_stats_btn = QPushButton("Export Stats")

        # Main Layout
        layout = QVBoxLayout()
        layout.addLayout(self.control_panel)
        layout.addWidget(self.packet_table)
        layout.addWidget(self.stats_label)
        layout.addWidget(self.stats_text)
        layout.addWidget(self.canvas)
        layout.addLayout(self.export_panel)
        self.setLayout(layout)

    def setup_connections(self):
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_pcap_btn.clicked.connect(self.save_to_pcap)
        self.export_stats_btn.clicked.connect(self.export_stats)

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

    def start_capture(self):
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
        self.capture_module.stop_capture()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        logger.info("Capture stopped")

    def update_packet_list(self):
        try:
            new_packets = self.capture_module.get_packets()
            if not new_packets:
                return

            self.packet_table.setUpdatesEnabled(False)
            current_row_count = self.packet_table.rowCount()
            self.packet_table.setRowCount(current_row_count + len(new_packets))

            for i, packet in enumerate(new_packets, current_row_count):
                packet_info = self.packet_processing_module.process_packet(packet)
                if not packet_info:
                    continue

                items = [
                    datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f'),
                    packet_info.get('src_ip', ''),
                    packet_info.get('dst_ip', ''),
                    packet_info.get('protocol', ''),
                    str(packet_info.get('src_port', '')),
                    str(packet_info.get('dst_port', '')),
                    str(len(packet_info.get('payload', b''))),
                    packet_info.get('http_info', {}).get('method', '')
                ]
                
                for col, text in enumerate(items):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.packet_table.setItem(i, col, item)

            self.packet_table.setUpdatesEnabled(True)
            self.update_statistics()
            self.update_plots()
            
        except Exception as e:
            logger.error(f"Packet update error: {e}")

    def update_statistics(self):
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
        stats = self.statistics_module.get_statistics()
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        if stats['protocol_counts']:
            ax.bar(stats['protocol_counts'].keys(), 
                  stats['protocol_counts'].values())
            ax.set_title("Traffic by Protocol")
            self.canvas.draw()

    def save_to_pcap(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "", "PCAP Files (*.pcap)")
            
        if filename:
            packets = [p for p in self.packets if p[1]]
            if packets:
                success = self.data_storage_module.save_to_pcap(packets, filename)
                if success:
                    QMessageBox.information(self, "Success", f"Saved {len(packets)} packets")
                else:
                    QMessageBox.warning(self, "Error", "Failed to save packets")
            else:
                QMessageBox.warning(self, "Error", "No packets to save!")

    def export_stats(self):
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
        if self.capture_module.running:
            reply = QMessageBox.question(
                self, 'Confirm Exit',
                'Capture is running. Are you sure you want to exit?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.No:
                event.ignore()
                return
                
        self.timer.stop()
        self.main_module.stop()
        event.accept()