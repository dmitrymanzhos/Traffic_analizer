from scapy.all import wrpcap, rdpcap
import os
from loguru import logger
from typing import List, Optional, Union
from scapy.packet import Packet

class DataStorageModule:
    def save_to_pcap(self, packets: Union[List[Packet], Packet], filename: str) -> bool:
        """Сохранение в PCAP-файл"""
        try:
            if not packets:
                logger.warning("No packets to save")
                return False
                
            os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
            wrpcap(filename, packets, append=os.path.exists(filename))
            logger.success(f"Saved {len(packets)} packets to {filename}")
            return True
        except PermissionError:
            logger.error(f"Permission denied: {filename}")
            return False
        except Exception as e:
            logger.error(f"PCAP save error: {e}")
            return False
    
    def save_session_to_pcap(self, packets: List[Packet], prefix="capture") -> bool:
        """Автоматическое сохранение сессии с timestamp"""
        try:
            if not packets:
                logger.warning("No packets to save in session")
                return False
                
            filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            return self.save_to_pcap(packets, filename) # используем прошлый метод
        except Exception as e:
            logger.error(f"Session save error: {e}")
            return False

    def load_from_pcap(self, filename: str) -> List[Packet]:
        """Загрузка из PCAP-файла """
        try:
            if not os.path.exists(filename):
                logger.error(f"File not found: {filename}")
                return []
                
            packets = rdpcap(filename)
            logger.info(f"Loaded {len(packets)} packets from {filename}")
            return packets
        except Exception as e:
            logger.error(f"PCAP load error: {e}")
            return []
    
    def save_session_to_pcap(self, packets: list, filename="session.pcap") -> bool:
        """Сохраняет все пакеты сессии в файл"""
        return self.save_to_pcap(packets, filename)