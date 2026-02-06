"""异常检测引擎

两级检测架构：
1. 规则引擎：频率异常、ID越界、负载异常
2. ML模型：Isolation Forest 无监督异常检测
"""

import time
from collections import Counter, defaultdict
from typing import List

import numpy as np

from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.config import settings


class RuleBasedDetector:
    """基于规则的快速异常检测"""

    VALID_CAN_IDS = {
        "0x0C0", "0x0C8", "0x130", "0x180", "0x1A0", "0x200",
        "0x260", "0x280", "0x320", "0x3E0", "0x7DF", "0x7E0",
    }

    def __init__(self):
        self.freq_threshold = settings.detector.frequency_threshold
        self.baseline_freq = {}  # msg_id -> 基线频率

    def check(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        alerts.extend(self._check_frequency(packets))
        alerts.extend(self._check_unknown_id(packets))
        alerts.extend(self._check_payload(packets))
        return alerts

    def _check_frequency(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测报文频率异常（DoS特征）"""
        alerts = []
        if len(packets) < 2:
            return alerts

        time_span = packets[-1].timestamp - packets[0].timestamp
        if time_span <= 0:
            return alerts

        id_counts = Counter(p.msg_id for p in packets if p.protocol == "CAN")
        if not id_counts:
            return alerts
        avg_per_id_freq = sum(id_counts.values()) / len(id_counts) / time_span

        for msg_id, count in id_counts.items():
            freq = count / time_span
            if freq > avg_per_id_freq * self.freq_threshold:
                ratio = freq / (avg_per_id_freq * self.freq_threshold)
                if ratio > 3.0:
                    severity = "critical"
                elif ratio > 1.5:
                    severity = "high"
                else:
                    severity = "medium"
                alerts.append(AnomalyEvent(
                    timestamp=packets[-1].timestamp,
                    anomaly_type="frequency_anomaly",
                    severity=severity,
                    confidence=min(ratio, 1.0),
                    protocol="CAN",
                    source_node=msg_id,
                    description=f"报文 {msg_id} 频率异常: {freq:.1f} pkt/s, "
                                f"每ID均值 {avg_per_id_freq:.1f} pkt/s, "
                                f"超出阈值 {self.freq_threshold}x",
                    detection_method="rule_frequency",
                ))
        return alerts

    def _check_unknown_id(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测未知CAN ID（Fuzzy攻击特征）"""
        alerts = []
        seen_unknown = set()
        for p in packets:
            if p.protocol != "CAN":
                continue
            if p.msg_id not in self.VALID_CAN_IDS and p.msg_id not in seen_unknown:
                seen_unknown.add(p.msg_id)
                alerts.append(AnomalyEvent(
                    timestamp=p.timestamp,
                    anomaly_type="unknown_can_id",
                    severity="high",
                    confidence=0.8,
                    protocol="CAN",
                    source_node=p.source,
                    description=f"检测到未知CAN ID: {p.msg_id}, 来源: {p.source}",
                    detection_method="rule_id_whitelist",
                ))
        return alerts

    def _check_payload(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测负载异常（全FF等Spoofing特征）"""
        alerts = []
        for p in packets:
            if p.protocol != "CAN" or not p.payload_hex:
                continue
            unique_bytes = set(
                p.payload_hex[i:i+2] for i in range(0, len(p.payload_hex), 2)
            )
            if len(unique_bytes) == 1 and len(p.payload_hex) >= 8:
                byte_val = list(unique_bytes)[0]
                if byte_val in ("ff", "FF", "00"):
                    severity = "critical"
                    confidence = 0.9
                else:
                    severity = "low"
                    confidence = 0.5
                alerts.append(AnomalyEvent(
                    timestamp=p.timestamp,
                    anomaly_type="payload_anomaly",
                    severity=severity,
                    confidence=confidence,
                    protocol="CAN",
                    source_node=p.source,
                    target_node=p.msg_id,
                    description=f"报文 {p.msg_id} 负载全为 0x{byte_val}, "
                                f"疑似Spoofing攻击",
                    detection_method="rule_payload",
                ))
        return alerts


class IsolationForestDetector:
    """基于Isolation Forest的无监督异常检测"""

    def __init__(self):
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(
            contamination=settings.detector.iforest_contamination,
            random_state=42,
            n_estimators=100,
        )
        self.is_fitted = False

    def extract_features(self, packets: List[UnifiedPacket]) -> np.ndarray:
        """从报文列表提取数值特征向量"""
        if not packets:
            return np.array([]).reshape(0, 5)

        features = []
        for p in packets:
            try:
                if "." not in p.msg_id and p.msg_id.startswith("0x"):
                    msg_id_num = int(p.msg_id, 16)
                else:
                    msg_id_num = hash(p.msg_id) % 0xFFF
            except ValueError:
                msg_id_num = hash(p.msg_id) % 0xFFF
            payload_len = len(p.payload_hex) // 2 if p.payload_hex else 0
            payload_entropy = self._byte_entropy(p.payload_hex)
            proto_num = {"CAN": 0, "ETH": 1, "V2X": 2}.get(p.protocol, 3)
            domain_num = {
                "powertrain": 0, "chassis": 1,
                "body": 2, "infotainment": 3, "v2x": 4,
            }.get(p.domain, 5)
            features.append([
                msg_id_num, payload_len, payload_entropy,
                proto_num, domain_num,
            ])
        return np.array(features)

    @staticmethod
    def _byte_entropy(hex_str: str) -> float:
        if not hex_str or len(hex_str) < 2:
            return 0.0
        byte_vals = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
        counts = Counter(byte_vals)
        total = len(byte_vals)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy

    def fit(self, normal_packets: List[UnifiedPacket]):
        """用正常流量训练模型"""
        features = self.extract_features(normal_packets)
        if len(features) > 0:
            self.model.fit(features)
            self.is_fitted = True

    def predict(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测异常报文"""
        if not self.is_fitted or not packets:
            return []

        features = self.extract_features(packets)
        scores = self.model.decision_function(features)
        preds = self.model.predict(features)

        alerts = []
        for i, (pred, score) in enumerate(zip(preds, scores)):
            if pred == -1:
                p = packets[i]
                if score < -0.05:
                    ml_severity = "critical"
                elif score < -0.03:
                    ml_severity = "high"
                elif score < -0.02:
                    ml_severity = "medium"
                else:
                    ml_severity = "low"
                alerts.append(AnomalyEvent(
                    timestamp=p.timestamp,
                    anomaly_type="ml_anomaly",
                    severity=ml_severity,
                    confidence=round(min(abs(score), 1.0), 3),
                    protocol=p.protocol,
                    source_node=p.source,
                    target_node=p.msg_id,
                    description=(
                        f"ML模型检测到异常: {p.protocol} "
                        f"报文 {p.msg_id}, 异常分数 {score:.3f}"
                    ),
                    detection_method="isolation_forest",
                ))
        return alerts


class AnomalyDetectorService:
    """统一异常检测入口"""

    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = IsolationForestDetector()

    def train(self, normal_packets: List[UnifiedPacket]):
        """用正常流量训练ML模型"""
        self.ml_detector.fit(normal_packets)

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """执行两级检测"""
        alerts = []

        if settings.detector.rule_enabled:
            alerts.extend(self.rule_detector.check(packets))

        if settings.detector.ml_enabled and self.ml_detector.is_fitted:
            alerts.extend(self.ml_detector.predict(packets))

        # 按置信度降序排列
        alerts.sort(key=lambda a: a.confidence, reverse=True)
        return alerts