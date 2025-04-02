# gui_module.py
import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QLineEdit, QComboBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QTimer
import matplotlib.pyplot as plt #  Для визуализации (установить: pip install matplotlib)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class GuiModule(QWidget):
    def __init__(self, capture_module, packet_processing_module, data_storage_module, statistics_module, main_module):
        super().__init__()
        self.capture_module = capture_module
        self.packet_processing_module = packet_processing_module
        self.data_storage_module = data_storage_module
        self.statistics_module = statistics_module
        self.main_module = main_module #  Для связи с main.py
        self.packets = []
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_packet_list)
        self.timer.start(1000) #  Обновление каждые 1 секунду

    def init_ui(self):
        self.setWindowTitle('Network Traffic Analyzer')

        # Interface selection
        self.interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        self.interface_combo.currentIndexChanged.connect(self.update_bpf_filter)

        # BPF Filter
        self.filter_label = QLabel("BPF Filter:")
        self.filter_edit = QLineEdit()
        self.filter_edit.returnPressed.connect(self.update_bpf_filter) #  Apply filter on Enter

        self.start_button = QPushButton('Start Capture')
        self.stop_button = QPushButton('Stop Capture')
        self.save_pcap_button = QPushButton('Save to PCAP')
        self.load_pcap_button = QPushButton('Load from PCAP')
        self.save_stream_button = QPushButton('Save Stream')
        self.reset_statistics_button = QPushButton('Reset Statistics')
        self.generate_report_button = QPushButton('Generate Report')

        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.save_pcap_button.clicked.connect(self.save_to_pcap)
        self.load_pcap_button.clicked.connect(self.load_from_pcap)
        self.save_stream_button.clicked.connect(self.save_stream)
        self.reset_statistics_button.clicked.connect(self.reset_statistics)
        self.generate_report_button.clicked.connect(self.generate_report)

        # Packet Table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8) #  Пример: Source IP, Dest IP, Protocol, Length, ...
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Dest Port", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.itemSelectionChanged.connect(self.packet_selected) #  Обработка выбора строки

        # Statistics display (Placeholder)
        self.statistics_label = QLabel("Statistics:")
        self.statistics_text = QLabel("Waiting for data...") #  TODO: Use QTextEdit or other rich text widget.
        self.statistics_display_layout = QVBoxLayout()
        self.statistics_display_layout.addWidget(self.statistics_label)
        self.statistics_display_layout.addWidget(self.statistics_text)

        # Visualization (Placeholder)
        self.visualization_layout = QVBoxLayout()
        self.create_visualization() # Initialize Matplotlib figure here.

        # Layouts
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.interface_label)
        controls_layout.addWidget(self.interface_combo)
        controls_layout.addWidget(self.filter_label)
        controls_layout.addWidget(self.filter_edit)
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addWidget(self.save_pcap_button)
        controls_layout.addWidget(self.load_pcap_button)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.save_stream_button)
        buttons_layout.addWidget(self.reset_statistics_button)
        buttons_layout.addWidget(self.generate_report_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.packet_table)
        main_layout.addLayout(self.statistics_display_layout)
        main_layout.addLayout(self.visualization_layout)
        main_layout.addLayout(buttons_layout)

        self.setLayout(main_layout)
        self.setGeometry(100, 100, 1200, 800) #  Set size

    def refresh_interfaces(self):
        self.interface_combo.clear()
        interfaces = self.capture_module.get_interfaces()
        for iface in interfaces:
            self.interface_combo.addItem(iface)

    def update_bpf_filter(self):
        #  Применяем фильтр
        self.start_capture() # Restart capture with new filter.  (or just stop/start)
        #TODO:  Переделать на изменение текущего фильтра в работающем захвате

    def start_capture(self):
        interface = self.interface_combo.currentText()
        bpf_filter = self.filter_edit.text()
        if interface:
            if self.capture_module.start_capture(interface, bpf_filter):
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                print(f"Capturing on {interface} with filter: {bpf_filter}")
            else:
                self.show_error_message("Failed to start capture.")
        else:
            self.show_error_message("Please select an interface.")

    def stop_capture(self):
        self.capture_module.stop_capture()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        print("Capture stopped")

    def update_packet_list(self):
        new_packets = self.capture_module.get_packets()
        if not new_packets:
            return

        #  Обрабатываем новые пакеты
        for (header, packet_data) in new_packets:
            packet_info = self.packet_processing_module.process_packet(packet_data)

            if packet_info:
                #  Реконструируем TCP поток
                if packet_info['protocol'] == 'TCP':
                   stream = self.packet_processing_module.reconstruct_tcp_stream(packet_info)
                   if stream:
                       packet_info['stream_key'] = tuple(sorted(((packet_info['src_ip'], packet_info['src_port']), (packet_info['dst_ip'], packet_info['dst_port']))))  # Ключ потока для статистики
                   http_info = self.packet_processing_module.extract_http_info(packet_info['payload'])
                   if http_info:
                       packet_info['http_info'] = http_info
                #TODO:  QUIC stream reconstruction

                #  Обновляем статистику
                self.statistics_module.update_statistics(packet_info)

                #  Сохраняем сырые данные в PCAP (необязательно, но удобно)
                #  (Чтобы не было ошибок, записываем в PCAP только те пакеты, что прошли фильтр)
                if self.filter_edit.text(): #TODO:  Проверить, подходит ли пакет под фильтр (иначе сохранять все подряд)
                    self.data_storage_module.save_to_pcap((header, packet_data), "captured.pcap")  # Сохраняем в pcap

                self.packets.append((header, packet_info))  # Добавляем в список для отображения

        #  Обновляем таблицу
        self.packet_table.setRowCount(0)
        for i, (header, packet_info) in enumerate(self.packets):
            self.packet_table.insertRow(i)
            timestamp = datetime.fromtimestamp(header.ts.tv_sec + header.ts.tv_usec / 1000000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
            self.packet_table.setItem(i, 0, QTableWidgetItem(timestamp))
            self.packet_table.setItem(i, 1, QTableWidgetItem(packet_info.get('src_ip', '')))
            self.packet_table.setItem(i, 2, QTableWidgetItem(packet_info.get('dst_ip', '')))
            self.packet_table.setItem(i, 3, QTableWidgetItem(packet_info.get('protocol', '')))
            self.packet_table.setItem(i, 4, QTableWidgetItem(str(packet_info.get('src_port', ''))))
            self.packet_table.setItem(i, 5, QTableWidgetItem(str(packet_info.get('dst_port', ''))))
            self.packet_table.setItem(i, 6, QTableWidgetItem(str(len(packet_info.get('payload', b'')))))

            info_text = ""
            if 'http_info' in packet_info and packet_info['http_info']:
                info_text += f"HTTP {packet_info['http_info']['method']}"
            self.packet_table.setItem(i, 7, QTableWidgetItem(info_text))

        #  Обновляем статистику
        self.update_statistics_display()
        self.update_visualization()

    def update_statistics_display(self):
        statistics = self.statistics_module.get_statistics()
        #  Форматируем статистику для отображения
        text = f"Packets captured: {statistics['packet_count']}\n"
        text += f"Bytes captured: {statistics['byte_count']}\n"
        text += "Protocols:\n"
        for protocol, count in statistics['protocol_counts'].items():
            text += f"  {protocol}: {count}\n"
        text += "IP Addresses:\n"
        for ip, counts in statistics['ip_counts'].items():
            text += f"  {ip}: In: {counts['in']}, Out: {counts['out']}\n"
        self.statistics_text.setText(text)

    def save_to_pcap(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "captured.pcap", "PCAP Files (*.pcap)")
        if filename:
            try:
                #  Сохраняем все захваченные пакеты.  (Можно добавить фильтрацию здесь)
                #TODO:  Сохранять пакеты сразу, а не в конце, чтобы можно было прервать захват
                # for header, packet_data in self.capture_module.get_packets(): #  Использовать  self.packets
                #    self.data_storage_module.save_to_pcap((header, packet_data), filename)
                self.show_message("PCAP saved successfully.")
            except Exception as e:
                self.show_error_message(f"Error saving PCAP: {e}")

    def load_from_pcap(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load PCAP File", "", "PCAP Files (*.pcap)")
        if filename:
            try:
                loaded_packets = self.data_storage_module.load_from_pcap(filename)
                self.packets = [] # Очищаем список
                for ts, packet_data in loaded_packets:
                    #  Обрабатываем пакеты, аналогично тому, как это делается при захвате.
                    packet_info = self.packet_processing_module.process_packet(packet_data)
                    if packet_info:
                        #  Реконструируем потоки
                        if packet_info['protocol'] == 'TCP':
                            stream = self.packet_processing_module.reconstruct_tcp_stream(packet_info)
                            if stream:
                                packet_info['stream_key'] = tuple(sorted(((packet_info['src_ip'], packet_info['src_port']), (packet_info['dst_ip'], packet_info['dst_port']))))  # Клю