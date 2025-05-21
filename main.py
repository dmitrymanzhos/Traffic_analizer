#!/usr/bin/env python3
import sys
import os
from datetime import datetime
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication
from capture_module import CaptureModule
from packet_processing_module import PacketProcessingModule
from data_storage_module import DataStorageModule
from statistics_module import StatisticsModule
from gui_module import GuiModule
from loguru import logger
import atexit

# Configure runtime directory for Linux systems
os.makedirs(os.environ.get('XDG_RUNTIME_DIR', f'/tmp/runtime-{os.getuid()}'), 
            mode=0o700, exist_ok=True)

class MainModule:
    def __init__(self):
        logger.info("Initializing application modules")
        
        try:
            self.capture_module = CaptureModule()
            self.packet_processing_module = PacketProcessingModule()
            self.data_storage_module = DataStorageModule()
            self.statistics_module = StatisticsModule(self.packet_processing_module)

            atexit.register(self._save_on_exit) # обработчик завершения
            
            self.gui = GuiModule(
                self.capture_module,
                self.packet_processing_module,
                self.data_storage_module,
                self.statistics_module,
                self
            )
            # atexit.register(self._save_before_exit)  # Автосохранение
            self.health_check_timer = QTimer()
            self.health_check_timer.timeout.connect(self.check_connection_health)
            self.health_check_timer.start(5000)  # Проверка сотстояния потоков каждые 5 секунд
            

        except Exception as e:
            logger.critical(f"Module initialization failed: {e}")
            raise

    def start(self):
        """Запуск GUI"""
        try:
            self.gui.show()
            logger.info("Application started successfully")
        except Exception as e:
            logger.error(f"Failed to start GUI: {e}")
            raise

    def stop(self):
        logger.info("Stopping application")
        try:
            if hasattr(self, 'gui'):
                self.gui.stop_capture() 
            if hasattr(self, 'capture_module'):
                self.capture_module.stop_capture()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            
    # def _save_before_exit(self):
    #     packets = self.capture_module.get_packets()
    #     if packets:
    #         self.data_storage_module.save_session_to_pcap(
    #             packets,
    #             f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    #         )

    def check_connection_health(self):
        """Проверка состояния соединений"""
        try:
            issues = self.packet_processing_module.get_connection_issues()
            if issues:
                logger.warning(f"Connection issues detected: {issues}")
                if 'timeouts' in issues:
                    self.gui.show_warning(f"Timed out streams: {len(issues['timeouts'])}")
            return True
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return False

    def _save_on_exit(self):
        """Автоматическое сохранение при завершении"""
        if hasattr(self, 'capture_module'):
            packets = self.capture_module.get_all_packets()
            if packets:
                logger.info(f"Saving {len(packets)} packets before exit")
                self.data_storage_module.save_session_to_pcap(packets)
            else:
                logger.info("No packets to save on exit")


def main():
    try:
        # логи
        logger.add("/var/log/network_analyzer.log", rotation="1 MB", retention="7 days")
        app = QApplication(sys.argv)
        main_module = MainModule()
        
        main_module.start()
        sys.exit(app.exec_())
        
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
        main_module.stop()
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        if 'main_module' in locals():
            main_module.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
