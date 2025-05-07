# main.py
import sys
from PyQt5.QtWidgets import QApplication
from capture_module import CaptureModule
from packet_processing_module import PacketProcessingModule
from data_storage_module import DataStorageModule
from statistics_module import StatisticsModule
from gui_module import GuiModule

import os
# if not os.environ.get('XDG_RUNTIME_DIR'):
    # os.environ['XDG_RUNTIME_DIR'] = f'/tmp/runtime-{os.getuid()}'
    # os.makedirs(os.environ['XDG_RUNTIME_DIR'], exist_ok=True)
os.environ['XDG_RUNTIME_DIR'] = f'/tmp/runtime-{os.getuid()}'
os.makedirs(os.environ['XDG_RUNTIME_DIR'], mode=0o700, exist_ok=True)

class MainModule:
    def __init__(self):
        # Создаем экземпляры всех модулей
        self.capture_module = CaptureModule()
        self.packet_processing_module = PacketProcessingModule()
        self.data_storage_module = DataStorageModule()
        self.statistics_module = StatisticsModule()

        # Инициализируем GUI и передаем модули в интерфейс
        self.gui = GuiModule(
            self.capture_module,
            self.packet_processing_module,
            self.data_storage_module,
            self.statistics_module,
            self
        )

    def start(self):
        # Показываем GUI
        self.gui.show()

    def stop(self):
        # Останавливаем захват при закрытии приложения
        self.capture_module.stop_capture()


if __name__ == "__main__":
    # Инициализация приложения
    app = QApplication(sys.argv)
    main_module = MainModule()

    try:
        main_module.start()
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        print("Application terminated by user.")
        main_module.stop()
    except Exception as e:
        print(f"Unexpected error: {e}")
        main_module.stop()