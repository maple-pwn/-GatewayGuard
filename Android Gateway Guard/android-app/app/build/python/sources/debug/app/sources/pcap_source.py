"""PCAP/BLF 离线文件回放数据源

支持导入 .pcap 和 .blf 格式的抓包文件进行离线分析。
"""

import logging
import time
from collections import deque
from pathlib import Path
from typing import List

from app.models.packet import UnifiedPacket
from app.platform import is_android_env
from app.services.traffic_parser import CANParser
from app.sources.base import DataSource

logger = logging.getLogger(__name__)


class PcapSource(DataSource):
    """从 PCAP/BLF 文件读取报文。"""

    def __init__(self, file_path: str = ""):
        super().__init__()
        self.file_path = file_path
        self._buffer: deque[UnifiedPacket] = deque(maxlen=50000)
        self._parser = CANParser()

    async def start(self) -> None:
        if self._running:
            return
        if not self.file_path:
            raise ValueError("file_path is required")
        if not Path(self.file_path).is_file():
            raise ValueError(f"Import file does not exist: {self.file_path}")
        self._running = True
        self._load_file()
        logger.info("PCAP source loaded: %s (%d packets)",
                     self.file_path, len(self._buffer))

    async def stop(self) -> None:
        self._running = False
        self._buffer.clear()
        logger.info("PCAP source stopped")

    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        result = []
        for _ in range(min(max_count, len(self._buffer))):
            result.append(self._buffer.popleft())
        return result

    def _load_file(self) -> None:
        """根据文件扩展名选择加载方式。"""
        path = self.file_path.lower()
        if path.endswith(".blf"):
            self._load_blf()
        elif path.endswith(".pcap") or path.endswith(".pcapng"):
            self._load_pcap()
        elif path.endswith(".asc"):
            self._load_asc()
        else:
            raise ValueError(f"Unsupported file format: {path}")

    def _load_blf(self) -> None:
        """加载 Vector BLF 格式的 CAN 日志。"""
        if is_android_env():
            logger.warning("BLF support is experimental on Android")
        try:
            import can
            with can.BLFReader(self.file_path) as reader:
                for msg in reader:
                    msg_id = f"0x{msg.arbitration_id:03X}"
                    payload_hex = msg.data.hex().upper()
                    pkt = self._parser.parse(
                        msg_id=msg_id,
                        payload_hex=payload_hex,
                        timestamp=msg.timestamp or time.time(),
                    )
                    self._buffer.append(pkt)
        except ImportError as exc:
            raise RuntimeError(
                "BLF import requires python-can (experimental on Android)."
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"BLF import failed: {exc}") from exc

    def _load_pcap(self) -> None:
        """加载 PCAP 格式的抓包。

        - SocketCAN 链路类型 (linktype 227) 或包含 scapy ``CAN`` 层的报文
          按 CAN 帧解析，写入 ``protocol="CAN"`` + 真实 ``msg_id``，让基于
          CAN 族的检测器（Timing/Replay/RPM/Gear/IDBehavior/Payload/IForest）
          能够建模和告警。
        - 其它链路（Ethernet / SLL 等）作为 ``protocol="ETH"`` 入库，并尽量
          填充真实的 src/dst/EtherType/IP/端口；``msg_id`` 不再用包长度伪造。
        """
        try:
            from scapy.all import PcapReader
        except ImportError as exc:
            raise RuntimeError("PCAP import requires scapy.") from exc

        try:
            from scapy.layers.can import CAN as ScapyCAN
        except Exception:
            ScapyCAN = None

        try:
            with PcapReader(self.file_path) as reader:
                linktype = getattr(reader, "linktype", None)
                for pkt in reader:
                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                    if ScapyCAN is not None and pkt.haslayer(ScapyCAN):
                        self._buffer.append(self._unpack_can_frame(pkt[ScapyCAN], ts))
                        continue
                    self._buffer.append(self._unpack_eth_frame(pkt, ts, linktype))
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"PCAP import failed: {exc}") from exc

    def _unpack_can_frame(self, can_layer, ts: float) -> UnifiedPacket:
        raw_id = int(getattr(can_layer, "identifier", 0)) & 0x1FFFFFFF
        msg_id = f"0x{raw_id:03X}"
        data_field = getattr(can_layer, "data", b"") or b""
        try:
            payload_hex = bytes(data_field).hex().upper()
        except Exception:
            payload_hex = ""
        return self._parser.parse(
            msg_id=msg_id,
            payload_hex=payload_hex,
            timestamp=ts,
        )

    def _unpack_eth_frame(self, pkt, ts: float, linktype) -> UnifiedPacket:
        src = str(getattr(pkt, "src", "") or "unknown")
        dst = str(getattr(pkt, "dst", "") or "unknown")
        eth_type = int(getattr(pkt, "type", 0) or 0)

        ip_src = ip_dst = None
        sport = dport = None
        transport = "ETH"
        try:
            from scapy.layers.inet import IP, UDP, TCP

            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                ip_src = ip_layer.src
                ip_dst = ip_layer.dst
                if pkt.haslayer(UDP):
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                    transport = "UDP"
                elif pkt.haslayer(TCP):
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    transport = "TCP"
        except Exception:
            pass

        if dport is not None:
            msg_id = f"{transport.lower()}:{dport}"
        elif eth_type:
            msg_id = f"eth:0x{eth_type:04X}"
        else:
            msg_id = "eth:unknown"

        raw = bytes(pkt)
        payload_hex = raw.hex().upper()[:512]
        decoded = {
            "length": len(raw),
            "ether_type": f"0x{eth_type:04X}" if eth_type else "",
            "ip_src": ip_src or "",
            "ip_dst": ip_dst or "",
            "sport": sport,
            "dport": dport,
            "transport": transport,
        }
        domain = "infotainment" if transport in ("UDP", "TCP") else "unknown"

        return UnifiedPacket(
            timestamp=ts,
            protocol="ETH",
            source=src,
            destination=dst,
            msg_id=msg_id,
            payload_hex=payload_hex,
            payload_decoded=decoded,
            domain=domain,
            metadata={
                "source_file": self.file_path,
                "linktype": linktype,
                "transport": transport,
            },
        )

    def _load_asc(self) -> None:
        """加载 ASC 格式的 CAN 日志。"""
        if is_android_env():
            logger.warning("ASC support is experimental on Android")
        try:
            import can
            with can.ASCReader(self.file_path) as reader:
                for msg in reader:
                    msg_id = f"0x{msg.arbitration_id:03X}"
                    payload_hex = msg.data.hex().upper()
                    pkt = self._parser.parse(
                        msg_id=msg_id,
                        payload_hex=payload_hex,
                        timestamp=msg.timestamp or time.time(),
                    )
                    self._buffer.append(pkt)
        except ImportError as exc:
            raise RuntimeError(
                "ASC import requires python-can (experimental on Android)."
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"ASC import failed: {exc}") from exc
