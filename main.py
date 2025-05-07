#!/usr/bin/env python3
# main.py
import sys
import os
from PyQt5.QtWidgets import QApplication
from capture_module import CaptureModule
from packet_processing_module import PacketProcessingModule
from data_storage_module import DataStorageModule
from statistics_module import StatisticsModule
from gui_module import GuiModule
from loguru import logger

# Configure runtime directory for Linux systems
os.makedirs(os.environ.get('XDG_RUNTIME_DIR', f'/tmp/runtime-{os.getuid()}'), 
            mode=0o700, exist_ok=True)

class MainModule:
    def __init__(self):
        logger.info("Initializing application modules")
        
        # Initialize modules with error handling
        try:
            self.capture_module = CaptureModule()
            self.packet_processing_module = PacketProcessingModule()
            self.data_storage_module = DataStorageModule()
            self.statistics_module = StatisticsModule()
            
            self.gui = GuiModule(
                self.capture_module,
                self.packet_processing_module,
                self.data_storage_module,
                self.statistics_module,
                self
            )
        except Exception as e:
            logger.critical(f"Module initialization failed: {e}")
            raise

    def start(self):
        """Start the application GUI"""
        try:
            self.gui.show()
            logger.info("Application started successfully")
        except Exception as e:
            logger.error(f"Failed to start GUI: {e}")
            raise

    def stop(self):
        """Cleanup resources before exit"""
        logger.info("Stopping application")
        try:
            self.capture_module.stop_capture()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

def main():
    try:
        # Configure logging
        logger.add("network_analyzer.log", rotation="1 MB", retention="7 days")
        
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