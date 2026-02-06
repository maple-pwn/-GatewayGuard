"""CAN总线流量模拟器

模拟车载CAN网络的正常通信和攻击流量：
- 正常流量：周期性ECU报文（发动机、变速箱、车身控制等）
- 攻击流量：DoS、Fuzzy、Spoofing
"""

import random
import time
from typing import List

from app.models.packet import UnifiedPacket

# 正常CAN报文定义：(msg_id, source_ecu, domain, period_ms, dlc)
NORMAL_CAN_MESSAGES = [
    ("0x0C0", "ECM", "powertrain", 10, 8),     # 发动机转速/扭矩
    ("0x0C8", "ECM", "powertrain", 20, 8),     # 发动机温度
    ("0x130", "TCM", "powertrain", 20, 8),     # 变速箱档位
    ("0x180", "ABS", "chassis", 10, 8),        # 轮速
    ("0x1A0", "ESP", "chassis", 20, 8),        # 横摆角速度
    ("0x200", "EPS", "chassis", 10, 8),        # 转向角
    ("0x260", "BCM", "body", 100, 8),          # 车灯/车门状态
    ("0x280", "BCM", "body", 200, 4),          # 空调状态
    ("0x320", "ICM", "infotainment", 50, 8),   # 仪表盘显示
    ("0x3E0", "HU", "infotainment", 100, 8),   # 主机指令
    ("0x7DF", "DIAG", "body", 0, 8),           # OBD诊断广播
    ("0x7E0", "DIAG", "powertrain", 0, 8),     # 诊断请求
]


def _random_payload(dlc: int) -> str:
    return "".join(f"{random.randint(0, 255):02X}" for _ in range(dlc))


def _decode_engine_rpm(payload_hex: str) -> dict:
    b0 = int(payload_hex[0:2], 16)
    b1 = int(payload_hex[2:4], 16)
    rpm = ((b0 << 8) | b1) * 0.25
    return {"rpm": round(rpm, 1), "raw": payload_hex}


def generate_normal_can(count: int = 100, base_time: float = None) -> List[UnifiedPacket]:
    """生成正常CAN流量"""
    if base_time is None:
        base_time = time.time()

    packets = []
    for i in range(count):
        msg = random.choice(NORMAL_CAN_MESSAGES)
        msg_id, src, domain, _, dlc = msg
        payload = _random_payload(dlc)

        decoded = {"dlc": dlc, "raw": payload}
        if msg_id == "0x0C0":
            decoded = _decode_engine_rpm(payload)

        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.01,
            protocol="CAN",
            source=src,
            destination="BROADCAST",
            msg_id=msg_id,
            payload_hex=payload,
            payload_decoded=decoded,
            domain=domain,
            metadata={"bus": "CAN-H", "bitrate": 500000},
        ))
    return packets


def generate_dos_attack(count: int = 500, base_time: float = None) -> List[UnifiedPacket]:
    """模拟DoS攻击：高频发送同一ID报文淹没总线"""
    if base_time is None:
        base_time = time.time()

    target_id = "0x000"
    packets = []
    for i in range(count):
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.0002,  # 极高频率
            protocol="CAN",
            source="ATTACKER",
            destination="BROADCAST",
            msg_id=target_id,
            payload_hex=_random_payload(8),
            payload_decoded={"attack": "dos", "dlc": 8},
            domain="unknown",
            metadata={"bus": "CAN-H", "bitrate": 500000, "attack": True},
        ))
    return packets


def generate_fuzzy_attack(count: int = 200, base_time: float = None) -> List[UnifiedPacket]:
    """模拟Fuzzy攻击：随机ID和随机负载"""
    if base_time is None:
        base_time = time.time()

    packets = []
    for i in range(count):
        rand_id = f"0x{random.randint(0, 0x7FF):03X}"
        rand_dlc = random.randint(1, 8)
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.005,
            protocol="CAN",
            source="ATTACKER",
            destination="BROADCAST",
            msg_id=rand_id,
            payload_hex=_random_payload(rand_dlc),
            payload_decoded={"attack": "fuzzy", "dlc": rand_dlc},
            domain="unknown",
            metadata={"bus": "CAN-H", "attack": True},
        ))
    return packets


def generate_spoofing_attack(count: int = 100, base_time: float = None) -> List[UnifiedPacket]:
    """模拟Spoofing攻击：伪装合法ECU发送篡改报文"""
    if base_time is None:
        base_time = time.time()

    target = random.choice(NORMAL_CAN_MESSAGES)
    msg_id, src, domain, _, dlc = target

    packets = []
    for i in range(count):
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.02,
            protocol="CAN",
            source=src,
            destination="BROADCAST",
            msg_id=msg_id,
            payload_hex="FF" * dlc,
            payload_decoded={"attack": "spoofing", "spoofed_ecu": src},
            domain=domain,
            metadata={"bus": "CAN-H", "attack": True},
        ))
    return packets
