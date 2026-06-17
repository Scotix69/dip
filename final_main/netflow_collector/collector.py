import csv
import ipaddress
import json
import logging
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

# ── конфигурация ──────────────────────────────────────────────────────────────
LISTEN_HOST      = os.getenv("NETFLOW_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT      = int(os.getenv("NETFLOW_LISTEN_PORT", "2055"))
VM_URL           = os.getenv("VM_URL", "http://victoriametrics:8428").rstrip("/")
VM_WRITE_PATH    = os.getenv("VM_WRITE_PATH", "/write")
VM_TIMEOUT_SEC   = float(os.getenv("VM_TIMEOUT_SEC", "5"))
TEMPLATE_TTL_SEC = int(os.getenv("TEMPLATE_TTL_SEC", "3600"))
LOG_LEVEL        = os.getenv("LOG_LEVEL", "INFO").upper()

# Куда писать тайминги обработки пакетов. Файл монтируется томом из docker-compose
PROCESSING_TIMES_FILE = os.getenv("PROCESSING_TIMES_FILE", "/data/processing_times.csv")

# ── защита канала телеметрии ──────────────────────────────────────────────────
ALLOWED_EXPORTERS = {
    a.strip() for a in os.getenv("ALLOWED_EXPORTERS", "").split(",") if a.strip()
}
RATE_LIMIT_PPS = int(os.getenv("RATE_LIMIT_PPS", "0"))
SECURITY_LOG_VERBOSE = os.getenv("SECURITY_LOG_VERBOSE", "1") == "1"

# ── модель приёма ─────────────────────────────────────────────────────────────
PACKET_QUEUE_SIZE = int(os.getenv("PACKET_QUEUE_SIZE", "10000"))

# ── логирование ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log     = logging.getLogger("[collector]")
sec_log = logging.getLogger("[security]")     # для allowlist / rate-limit / replay
val_log = logging.getLogger("[validation]")   # для отбраковки записей
q_log   = logging.getLogger("[queue]")        # для событий очереди приём→обработка

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


# ── writer таймингов обработки ────────────────────────────────────────────────
class ProcessingTimesWriter:


    HEADER = ["start", "end", "duration_sec", "exporter", "flows", "vm_lines"]

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._ok = False
        self._init_file()

    def _init_file(self) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            file_exists = os.path.exists(self.path) and os.path.getsize(self.path) > 0
            if not file_exists:
                with open(self.path, "w", newline="", encoding="utf-8") as f:
                    csv.writer(f, delimiter=";").writerow(self.HEADER)
                log.info("Файл таймингов создан: %s", self.path)
            else:
                log.info("Файл таймингов уже существует, продолжаем запись: %s", self.path)
            self._ok = True
        except OSError as exc:
            log.warning("Не удалось подготовить файл таймингов %s: %s — запись отключена",
                        self.path, exc)
            self._ok = False

    def append(self, start_ts: float, end_ts: float, exporter: str, flows: int, vm_lines: int) -> None:
        if not self._ok:
            return
        start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat(timespec="microseconds")
        end_iso   = datetime.fromtimestamp(end_ts,   tz=timezone.utc).isoformat(timespec="microseconds")
        duration_sec = f"{end_ts - start_ts:.6f}"
        row = [start_iso, end_iso, duration_sec, exporter, str(flows), str(vm_lines)]
        try:
            with self._lock, open(self.path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(row)
                f.flush()
        except OSError as exc:
            log.warning("Не удалось дописать в файл таймингов %s: %s", self.path, exc)


# ── фильтр источников (allowlist + rate limit + расширенное логирование) ─────
class SecurityFilter:


    def __init__(self, allowlist: set[str], rate_limit_pps: int, verbose: bool) -> None:
        self.allowlist = set(allowlist)
        self.rate_limit = int(rate_limit_pps)
        self.verbose = bool(verbose)

        self._lock = threading.Lock()
        self._window: dict[str, list[int]] = {}  # exporter → [sec, count]

        self._dropped_by_allowlist: dict[str, int] = {}
        self._dropped_by_rate:      dict[str, int] = {}
        self._last_summary_at = time.time()

        if self.allowlist:
            sec_log.info("allowlist включён, доверенные источники: %s",
                         ", ".join(sorted(self.allowlist)))
        else:
            sec_log.info("allowlist выключен — пакеты принимаются от любых источников")
        if self.rate_limit > 0:
            sec_log.info("rate-limit включён: %d пакетов/с на источник", self.rate_limit)
        else:
            sec_log.info("rate-limit выключен")

    def check(self, exporter_ip: str) -> bool:
        """True = пакет пропускаем, False = отбрасываем."""
        if self.allowlist and exporter_ip not in self.allowlist:
            self._dropped_by_allowlist[exporter_ip] = self._dropped_by_allowlist.get(exporter_ip, 0) + 1
            if self.verbose:
                sec_log.warning("отбрасываю пакет: источник %s не в allowlist", exporter_ip)
            return False

        if self.rate_limit > 0:
            now_sec = int(time.time())
            with self._lock:
                w = self._window.get(exporter_ip)
                if w is None or w[0] != now_sec:
                    self._window[exporter_ip] = [now_sec, 1]
                else:
                    w[1] += 1
                    if w[1] > self.rate_limit:
                        self._dropped_by_rate[exporter_ip] = self._dropped_by_rate.get(exporter_ip, 0) + 1
                        if self.verbose:
                            sec_log.warning(
                                "отбрасываю пакет: превышен rate-limit для %s (%d > %d пакетов/с)",
                                exporter_ip, w[1], self.rate_limit
                            )
                        return False

        if time.time() - self._last_summary_at >= 60:
            self._emit_summary()
            self._last_summary_at = time.time()

        return True

    def _emit_summary(self) -> None:
        if self._dropped_by_allowlist:
            sec_log.info("сводка за минуту — отброшено allowlist'ом: %s",
                         dict(self._dropped_by_allowlist))
            self._dropped_by_allowlist.clear()
        if self._dropped_by_rate:
            sec_log.info("сводка за минуту — отброшено rate-limit'ом: %s",
                         dict(self._dropped_by_rate))
            self._dropped_by_rate.clear()


# ── контроль последовательных номеров (защита от replay) ────────────────────
class SequenceTracker:

    _RESTART_THRESHOLD = 1_000_000

    _UINT32_MAX = 0xFFFFFFFF
    _WRAP_WINDOW = 0x1000_0000

    def __init__(self, verbose: bool) -> None:
        self.verbose = bool(verbose)
        self._lock = threading.Lock()
        # ключ: (protocol, exporter, source_id) → последний seq
        self._last_seq: dict[tuple[str, str, int], int] = {}
        # счётчики аномалий за минуту
        self._replays = 0
        self._restarts = 0
        self._last_summary_at = time.time()

    def check(self, protocol: str, exporter: str, source_id: int, seq: int) -> None:
        """Проверяет seq-номер. Не блокирует пакет, только пишет в журнал."""
        key = (protocol, exporter, source_id)
        with self._lock:
            prev = self._last_seq.get(key)
            if prev is None:
                self._last_seq[key] = seq
                return

            if seq > prev:
                self._last_seq[key] = seq
                return

            if prev > self._UINT32_MAX - self._WRAP_WINDOW and seq < self._WRAP_WINDOW:
                sec_log.info(
                    "переполнение sequence: exporter=%s source_id=%s prev=%d → seq=%d (uint32 wrap)",
                    exporter, source_id, prev, seq,
                )
                self._last_seq[key] = seq
                return

            if prev - seq > self._RESTART_THRESHOLD:
                self._restarts += 1
                sec_log.info(
                    "рестарт экспортёра: exporter=%s source_id=%s seq упал с %d до %d",
                    exporter, source_id, prev, seq,
                )
                self._last_seq[key] = seq
                return

            self._replays += 1
            if self.verbose:
                sec_log.warning(
                    "возможный replay-пакет: exporter=%s source_id=%s seq=%d ≤ предыдущего=%d",
                    exporter, source_id, seq, prev,
                )

        if time.time() - self._last_summary_at >= 60:
            self._emit_summary()
            self._last_summary_at = time.time()

    def _emit_summary(self) -> None:
        if self._replays > 0 or self._restarts > 0:
            sec_log.info(
                "сводка sequence за минуту: возможных replay=%d, рестартов экспортёра=%d",
                self._replays, self._restarts,
            )
            self._replays = 0
            self._restarts = 0



def validate_record(record: dict[str, Any]) -> tuple[bool, str]:
    for k in ("bytes", "packets"):
        v = record.get(k)
        if isinstance(v, int) and v < 0:
            return False, f"{k} < 0 ({v})"

    for k in ("src_port", "dst_port"):
        v = record.get(k)
        if isinstance(v, int) and (v < 0 or v > 65535):
            return False, f"{k} вне диапазона 0..65535 ({v})"

    proto = record.get("protocol")
    if isinstance(proto, int) and (proto < 0 or proto > 255):
        return False, f"protocol вне диапазона 0..255 ({proto})"

    for k in ("src", "dst"):
        v = record.get(k)
        if isinstance(v, str) and v in ("0.0.0.0", "255.255.255.255"):
            return False, f"{k}={v} недопустим для потока"

    # VLAN ID — диапазон 0..4094 (IEEE 802.1Q)
    for k in ("vlan_id", "vlan_src", "vlan_dst"):
        v = record.get(k)
        if isinstance(v, int) and (v < 0 or v > 4094):
            return False, f"{k} вне диапазона 0..4094 ({v})"

    return True, ""


# ── VLAN enrichment для NetFlow v5 ────────────────────────────────────────────
# Способ 1 — V5_VLAN_IF_MAP: SNMP-индекс интерфейса → VLAN ID
# Способ 2 — V5_VLAN_SUBNET_MAP: IP-подсеть → VLAN ID (longest-prefix match)

def _load_if_vlan_map() -> dict[str, dict[int, int]]:
    raw = os.getenv("V5_VLAN_IF_MAP", "").strip()
    if not raw:
        log.info("V5_VLAN_IF_MAP не задан — enrichment по интерфейсу отключён")
        return {}
    try:
        data: dict[str, dict[str, int]] = json.loads(raw)
        result = {exporter: {int(k): int(v) for k, v in mapping.items()} for exporter, mapping in data.items()}
        total = sum(len(m) for m in result.values())
        log.info("V5_VLAN_IF_MAP загружен: %d экспортёров, %d правил", len(result), total)
        return result
    except Exception as exc:
        log.warning("V5_VLAN_IF_MAP ошибка парсинга (игнорируется): %s", exc)
        return {}


def _load_subnet_vlan_map() -> list[tuple[ipaddress.IPv4Network, int]]:
    raw = os.getenv("V5_VLAN_SUBNET_MAP", "").strip()
    if not raw:
        log.info("V5_VLAN_SUBNET_MAP не задан — enrichment по подсети отключён")
        return []
    try:
        data: dict[str, int] = json.loads(raw)
        entries = sorted(
            [(ipaddress.IPv4Network(cidr, strict=False), int(vid)) for cidr, vid in data.items()],
            key=lambda x: x[0].prefixlen, reverse=True,
        )
        log.info("V5_VLAN_SUBNET_MAP загружен: %d подсетей", len(entries))
        return entries
    except Exception as exc:
        log.warning("V5_VLAN_SUBNET_MAP ошибка парсинга (игнорируется): %s", exc)
        return []


_IF_VLAN_MAP: dict[str, dict[int, int]] = _load_if_vlan_map()
_SUBNET_VLAN_MAP: list[tuple[ipaddress.IPv4Network, int]] = _load_subnet_vlan_map()


def _enrich_v5_vlan(record: dict[str, Any]) -> None:
    """Добавляет vlan_id в запись NetFlow v5 через interface-map или subnet-map."""
    if _IF_VLAN_MAP:
        exporter = record.get("exporter", "")
        input_if = record.get("input_if")
        if isinstance(input_if, int):
            vlan = (_IF_VLAN_MAP.get(exporter, {}).get(input_if)
                    or _IF_VLAN_MAP.get("*", {}).get(input_if))
            if vlan is not None:
                record["vlan_id"] = vlan
                log.debug("v5 VLAN enrichment (interface): exporter=%s if=%s → vlan_id=%s", exporter, input_if, vlan)
                return

    if _SUBNET_VLAN_MAP:
        for ip_key in ("src", "dst"):
            ip_str = record.get(ip_key)
            if not ip_str:
                continue
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            for network, vlan_id in _SUBNET_VLAN_MAP:
                if ip_obj in network:
                    record["vlan_id"] = vlan_id
                    log.debug("v5 VLAN enrichment (subnet): %s ∈ %s → vlan_id=%s", ip_str, network, vlan_id)
                    return


# ── таблицы полей NetFlow v9 и IPFIX ─────────────────────────────────────────
NFV9_FIELD_ALIASES: dict[int, str] = {
    1: "bytes", 2: "packets", 4: "protocol", 5: "tos", 6: "tcp_flags",
    7: "src_port", 8: "src", 9: "src_mask", 10: "input_if",
    11: "dst_port", 12: "dst", 13: "dst_mask", 14: "output_if",
    15: "next_hop", 16: "src_as", 17: "dst_as",
    21: "last_switched", 22: "first_switched",
    23: "out_bytes", 24: "out_packets",
    27: "src", 28: "dst", 29: "src_mask", 30: "dst_mask",
    32: "icmp_type", 56: "src_mac", 57: "dst_mac",
    58: "vlan_src", 59: "vlan_dst", 60: "ip_version", 61: "direction",
    80: "dst_mac", 81: "src_mac", 85: "bytes", 86: "packets",
    148: "flow_id", 152: "flow_start_msec", 153: "flow_end_msec",
    323: "observation_time_msec",
}

IPFIX_FIELD_ALIASES: dict[int, str] = {
    1: "bytes", 2: "packets", 4: "protocol", 5: "tos", 6: "tcp_flags",
    7: "src_port", 8: "src", 10: "input_if",
    11: "dst_port", 12: "dst", 14: "output_if",
    15: "next_hop", 16: "src_as", 17: "dst_as",
    21: "last_switched", 22: "first_switched",
    23: "out_bytes", 24: "out_packets",
    27: "src", 28: "dst", 29: "src_mask", 30: "dst_mask",
    56: "src_mac", 57: "dst_mac",
    58: "vlan_id", 59: "post_vlan_id", 60: "ip_version", 61: "direction",
    80: "dst_mac", 81: "src_mac", 85: "bytes", 86: "packets",
    148: "flow_id", 152: "flow_start_msec", 153: "flow_end_msec",
    154: "flow_start_usec", 155: "flow_end_usec",
    156: "flow_start_nsec", 157: "flow_end_nsec",
    243: "dot1q_vlan_id", 245: "dot1q_customer_vlan_id",
    254: "post_dot1q_vlan_id", 255: "post_dot1q_customer_vlan_id",
    323: "observation_time_msec",
}

FIELD_KEYS = {
    "bytes", "packets", "out_bytes", "out_packets",
    "tcp_flags", "tos", "src_as", "dst_as",
    "first_switched", "last_switched",
    "flow_start_msec", "flow_end_msec",
    "flow_start_usec", "flow_end_usec",
    "flow_start_nsec", "flow_end_nsec",
    "observation_time_msec",
}

TAG_KEYS = {
    "export_protocol", "exporter", "src", "dst",
    "src_port", "dst_port", "protocol",
    "vlan_id", "vlan_src", "vlan_dst", "post_vlan_id",
    "dot1q_vlan_id", "dot1q_customer_vlan_id",
    "post_dot1q_vlan_id", "post_dot1q_customer_vlan_id",
    "input_if", "output_if", "direction", "ip_version",
    "src_mask", "dst_mask", "src_mac", "dst_mac", "next_hop",
}

VLAN_CANDIDATE_KEYS = (
    "vlan_id", "vlan_src", "dot1q_vlan_id", "dot1q_customer_vlan_id",
    "post_vlan_id", "vlan_dst", "post_dot1q_vlan_id", "post_dot1q_customer_vlan_id",
)

IP_KEYS  = {"src", "dst", "next_hop"}
MAC_KEYS = {"src_mac", "dst_mac"}
VARIABLE_LENGTH = 0xFFFF


@dataclass(frozen=True)
class FieldSpec:
    field_type: int
    length: int
    enterprise: int | None = None


@dataclass
class Template:
    protocol: str
    fields: list[FieldSpec]
    record_len: int | None
    updated_at: float


@dataclass(frozen=True)
class ParsedFlow:
    record: dict[str, Any]
    timestamp_ns: int


class TemplateCache:
    def __init__(self, ttl_sec: int) -> None:
        self.ttl_sec = ttl_sec
        self._templates: dict[tuple[str, str, int, int], Template] = {}

    def put(self, protocol: str, exporter: str, domain_id: int, template_id: int, fields: list[FieldSpec]) -> None:
        record_len = None if any(f.length == VARIABLE_LENGTH for f in fields) else sum(f.length for f in fields)
        key = (protocol, exporter, domain_id, template_id)

        # ── Templates poisoning detection ──────────────────────────────────────
        old = self._templates.get(key)
        if old is not None and old.fields != fields:
            sec_log.warning(
                "обнаружено изменение структуры шаблона: protocol=%s exporter=%s "
                "domain=%s template=%s — старые поля: %d, новые поля: %d. "
                "Возможное переконфигурирование экспортёра либо templates-poisoning. "
                "Шаблон обновлён.",
                protocol, exporter, domain_id, template_id,
                len(old.fields), len(fields),
            )

        self._templates[key] = Template(protocol, fields, record_len, time.time())
        log.debug("template сохранён: protocol=%s exporter=%s domain=%s template=%s fields=%d record_len=%s",
                  protocol, exporter, domain_id, template_id, len(fields), record_len)

    def get(self, protocol: str, exporter: str, domain_id: int, template_id: int) -> Template | None:
        key = (protocol, exporter, domain_id, template_id)
        tpl = self._templates.get(key)
        if tpl is None:
            return None
        if time.time() - tpl.updated_at > self.ttl_sec:
            self._templates.pop(key, None)
            log.debug("template истёк: protocol=%s exporter=%s domain=%s template=%s", protocol, exporter, domain_id, template_id)
            return None
        return tpl


# ── вспомогательные функции ───────────────────────────────────────────────────

def _u(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=False)


def _decode_mac(data: bytes) -> str:
    return ":".join(f"{b:02x}" for b in data)


def _alias_for(protocol: str, spec: FieldSpec) -> str:
    if spec.enterprise is not None:
        return f"pen_{spec.enterprise}_ie_{spec.field_type}"
    if protocol == "ipfix":
        return IPFIX_FIELD_ALIASES.get(spec.field_type, f"ie_{spec.field_type}")
    if protocol == "netflow_v9":
        return NFV9_FIELD_ALIASES.get(spec.field_type, f"nf9_{spec.field_type}")
    return f"ie_{spec.field_type}"


def _decode_field(protocol: str, spec: FieldSpec, raw: bytes) -> tuple[str, Any]:
    alias = _alias_for(protocol, spec)
    if alias in IP_KEYS:
        if len(raw) == 4:
            return alias, str(ipaddress.IPv4Address(raw))
        if len(raw) == 16:
            return alias, str(ipaddress.IPv6Address(raw))
    if alias in MAC_KEYS and len(raw) == 6:
        return alias, _decode_mac(raw)
    if len(raw) <= 8:
        return alias, _u(raw)
    return alias, raw.hex()


def _escape_tag(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def _escape_key(value: str) -> str:
    return value.replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def _normalize_vlan(record: dict[str, Any]) -> None:
    if record.get("vlan_id") not in {None, ""}:
        return
    for key in VLAN_CANDIDATE_KEYS:
        value = record.get(key)
        if value not in {None, ""}:
            record["vlan_id"] = value
            return


def _record_timestamp_ns(record: dict[str, Any], fallback_ns: int) -> int:
    return time.time_ns()


def _to_vm_line(flow: ParsedFlow) -> str | None:
    """Формирует строку InfluxDB line protocol для записи в VictoriaMetrics."""
    record = dict(flow.record)
    _normalize_vlan(record)

    # Валидация записи перед формированием строки в хранилище
    ok, reason = validate_record(record)
    if not ok:
        exporter = record.get("exporter", "?")
        val_log.warning("отбрасываю запись от %s: %s | поля: src=%s dst=%s proto=%s",
                        exporter, reason,
                        record.get("src"), record.get("dst"), record.get("protocol"))
        return None

    tags: dict[str, Any] = {}
    fields: dict[str, int | float] = {}

    for key, value in record.items():
        if value is None or value == "":
            continue
        if key in FIELD_KEYS and isinstance(value, (int, float)):
            fields[key] = value
        elif key in TAG_KEYS:
            tags[key] = value

    fields["flow_count"] = 1  # синтетический счётчик для sum() в VM

    if not fields:
        return None

    record_ts_ns = _record_timestamp_ns(record, flow.timestamp_ns)
    tag_part  = "".join(f",{_escape_key(k)}={_escape_tag(v)}" for k, v in sorted(tags.items()))
    field_part = ",".join(
        f"{_escape_key(k)}={int(v)}i" if isinstance(v, int) or float(v).is_integer() else f"{_escape_key(k)}={float(v)}"
        for k, v in sorted(fields.items())
    )
    return f"netflow{tag_part} {field_part} {record_ts_ns}"


# ── парсинг пакетов ───────────────────────────────────────────────────────────

def _parse_v5(packet: bytes, exporter: str, timestamp_ns: int) -> list[ParsedFlow]:
    if len(packet) < 24:
        log.warning("слишком короткий v5 пакет от %s: %d байт", exporter, len(packet))
        return []
    version, count, _uptime, unix_secs, unix_nsecs, _seq, _et, _ei, _sampling = struct.unpack("!HHIIIIBBH", packet[:24])
    if version != 5:
        return []
    packet_ts_ns = int(unix_secs * 1_000_000_000 + unix_nsecs) or timestamp_ns
    flows: list[ParsedFlow] = []
    offset = 24
    rec = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")
    max_records = min(count, (len(packet) - offset) // rec.size)
    log.debug("v5 пакет от %s: %d флоу", exporter, max_records)
    for _ in range(max_records):
        vals = rec.unpack(packet[offset:offset + rec.size])
        offset += rec.size
        record: dict[str, Any] = {
            "export_protocol": "netflow_v5",
            "exporter": exporter,
            "src":          str(ipaddress.IPv4Address(vals[0])),
            "dst":          str(ipaddress.IPv4Address(vals[1])),
            "next_hop":     str(ipaddress.IPv4Address(vals[2])),
            "input_if":     vals[3],
            "output_if":    vals[4],
            "packets":      vals[5],
            "bytes":        vals[6],
            "first_switched": vals[7],
            "last_switched":  vals[8],
            "src_port":     vals[9],
            "dst_port":     vals[10],
            "tcp_flags":    vals[12],
            "protocol":     vals[13],
            "tos":          vals[14],
            "src_as":       vals[15],
            "dst_as":       vals[16],
            "src_mask":     vals[17],
            "dst_mask":     vals[18],
        }
        _enrich_v5_vlan(record)
        flows.append(ParsedFlow(record, packet_ts_ns))
    return flows


def _parse_template_records(data: bytes, ipfix: bool = False) -> list[tuple[int, list[FieldSpec]]]:
    offset = 0
    templates: list[tuple[int, list[FieldSpec]]] = []
    while offset + 4 <= len(data):
        template_id, field_count = struct.unpack("!HH", data[offset:offset + 4])
        if template_id == 0 and field_count == 0:
            break
        offset += 4
        fields: list[FieldSpec] = []
        ok = True
        for _ in range(field_count):
            if offset + 4 > len(data):
                ok = False
                break
            raw_type, length = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            enterprise = None
            field_type = raw_type
            if ipfix and raw_type & 0x8000:
                field_type = raw_type & 0x7FFF
                if offset + 4 > len(data):
                    ok = False
                    break
                enterprise = struct.unpack("!I", data[offset:offset + 4])[0]
                offset += 4
            fields.append(FieldSpec(field_type=field_type, length=length, enterprise=enterprise))
        if not ok:
            break
        if template_id >= 256 and fields:
            templates.append((template_id, fields))
    return templates


def _read_ipfix_variable_length(data: bytes, pos: int) -> tuple[int | None, int]:
    if pos >= len(data):
        return None, pos
    short_len = data[pos]
    pos += 1
    if short_len < 255:
        return short_len, pos
    if pos + 2 > len(data):
        return None, pos
    return struct.unpack("!H", data[pos:pos + 2])[0], pos + 2


def _parse_fixed_records_with_template(data: bytes, tpl: Template, timestamp_ns: int, exporter: str) -> list[ParsedFlow]:
    flows: list[ParsedFlow] = []
    if not tpl.record_len or tpl.record_len <= 0:
        return flows
    offset = 0
    while offset + tpl.record_len <= len(data):
        record_bytes = data[offset:offset + tpl.record_len]
        offset += tpl.record_len
        pos = 0
        record: dict[str, Any] = {"export_protocol": tpl.protocol, "exporter": exporter}
        for spec in tpl.fields:
            key, value = _decode_field(tpl.protocol, spec, record_bytes[pos:pos + spec.length])
            record[key] = value
            pos += spec.length
        flows.append(ParsedFlow(record, timestamp_ns))
    return flows


def _parse_variable_ipfix_records_with_template(data: bytes, tpl: Template, timestamp_ns: int, exporter: str) -> list[ParsedFlow]:
    flows: list[ParsedFlow] = []
    offset = 0
    while offset < len(data):
        record: dict[str, Any] = {"export_protocol": tpl.protocol, "exporter": exporter}
        pos = offset
        ok = True
        consumed_any = False
        for spec in tpl.fields:
            if spec.length == VARIABLE_LENGTH:
                value_len, pos = _read_ipfix_variable_length(data, pos)
                if value_len is None or pos + value_len > len(data):
                    ok = False
                    break
                raw = data[pos:pos + value_len]
                pos += value_len
            else:
                if pos + spec.length > len(data):
                    ok = False
                    break
                raw = data[pos:pos + spec.length]
                pos += spec.length
            consumed_any = True
            key, value = _decode_field(tpl.protocol, spec, raw)
            record[key] = value
        if not ok or not consumed_any or pos <= offset:
            break
        offset = pos
        flows.append(ParsedFlow(record, timestamp_ns))
        if all(byte == 0 for byte in data[offset:]):
            break
    return flows


def _parse_records_with_template(data: bytes, tpl: Template, timestamp_ns: int, exporter: str) -> list[ParsedFlow]:
    if tpl.record_len is None:
        if tpl.protocol == "ipfix":
            return _parse_variable_ipfix_records_with_template(data, tpl, timestamp_ns, exporter)
        return []
    return _parse_fixed_records_with_template(data, tpl, timestamp_ns, exporter)


def _parse_v9(packet: bytes, exporter: str, timestamp_ns: int, cache: TemplateCache,
              seq_tracker: "SequenceTracker | None" = None) -> list[ParsedFlow]:
    if len(packet) < 20:
        log.warning("слишком короткий v9 пакет от %s: %d байт", exporter, len(packet))
        return []
    version, _count, _uptime, unix_secs, seq, source_id = struct.unpack("!HHIIII", packet[:20])
    if version != 9:
        return []
    if seq_tracker is not None:
        seq_tracker.check("netflow_v9", exporter, source_id, seq)
    packet_ts_ns = unix_secs * 1_000_000_000 if unix_secs else timestamp_ns
    flows: list[ParsedFlow] = []
    offset = 20
    while offset + 4 <= len(packet):
        flowset_id, length = struct.unpack("!HH", packet[offset:offset + 4])
        if length < 4:
            break
        if offset + length > len(packet):
            log.warning("обрезанный v9 flowset: exporter=%s source_id=%s flowset=%s length=%s", exporter, source_id, flowset_id, length)
            break
        body = packet[offset + 4:offset + length]
        offset += length
        if flowset_id == 0:
            for tid, fields in _parse_template_records(body, ipfix=False):
                cache.put("netflow_v9", exporter, source_id, tid, fields)
                log.info("v9 template получен: exporter=%s source_id=%s template=%s fields=%d", exporter, source_id, tid, len(fields))
        elif flowset_id == 1:
            continue  # options template — пропускаем
        elif flowset_id >= 256:
            tpl = cache.get("netflow_v9", exporter, source_id, flowset_id)
            if tpl is None:
                log.warning("v9 template не найден: exporter=%s source_id=%s template=%s — ждём следующий template-пакет", exporter, source_id, flowset_id)
                continue
            batch = _parse_records_with_template(body, tpl, packet_ts_ns, exporter)
            log.debug("v9 данные: exporter=%s template=%s → %d флоу", exporter, flowset_id, len(batch))
            flows.extend(batch)
    return flows


def _parse_ipfix(packet: bytes, exporter: str, timestamp_ns: int, cache: TemplateCache,
                 seq_tracker: "SequenceTracker | None" = None) -> list[ParsedFlow]:
    if len(packet) < 16:
        log.warning("слишком короткий IPFIX пакет от %s: %d байт", exporter, len(packet))
        return []
    version, total_length, export_time, seq, domain_id = struct.unpack("!HHIII", packet[:16])
    if version != 10 or total_length < 16 or total_length > len(packet):
        return []
    if seq_tracker is not None:
        seq_tracker.check("ipfix", exporter, domain_id, seq)
    packet_ts_ns = export_time * 1_000_000_000 if export_time else timestamp_ns
    flows: list[ParsedFlow] = []
    offset = 16
    while offset + 4 <= total_length:
        set_id, set_len = struct.unpack("!HH", packet[offset:offset + 4])
        if set_len < 4:
            break
        if offset + set_len > total_length:
            log.warning("обрезанный IPFIX set: exporter=%s domain=%s set=%s length=%s", exporter, domain_id, set_id, set_len)
            break
        body = packet[offset + 4:offset + set_len]
        offset += set_len
        if set_id == 2:
            for tid, fields in _parse_template_records(body, ipfix=True):
                cache.put("ipfix", exporter, domain_id, tid, fields)
                log.info("IPFIX template получен: exporter=%s domain=%s template=%s fields=%d", exporter, domain_id, tid, len(fields))
        elif set_id == 3:
            continue  # options template — пропускаем
        elif set_id >= 256:
            tpl = cache.get("ipfix", exporter, domain_id, set_id)
            if tpl is None:
                log.warning("IPFIX template не найден: exporter=%s domain=%s template=%s — ждём следующий template-пакет", exporter, domain_id, set_id)
                continue
            batch = _parse_records_with_template(body, tpl, packet_ts_ns, exporter)
            log.debug("IPFIX данные: exporter=%s template=%s → %d флоу", exporter, set_id, len(batch))
            flows.extend(batch)
    return flows


def parse_packet(packet: bytes, addr: tuple[str, int], cache: TemplateCache,
                 seq_tracker: "SequenceTracker | None" = None) -> list[ParsedFlow]:
    if len(packet) < 2:
        return []
    version = struct.unpack("!H", packet[:2])[0]
    timestamp_ns = time.time_ns()
    exporter = addr[0]
    if version == 5:
        return _parse_v5(packet, exporter, timestamp_ns)
    if version == 9:
        return _parse_v9(packet, exporter, timestamp_ns, cache, seq_tracker)
    if version == 10:
        return _parse_ipfix(packet, exporter, timestamp_ns, cache, seq_tracker)
    log.warning("неизвестная версия NetFlow: version=%s от %s", version, addr)
    return []


# ── запись в VictoriaMetrics ──────────────────────────────────────────────────

class VictoriaWriter:
    def __init__(self, base_url: str, write_path: str, timeout_sec: float) -> None:
        self.url = base_url.rstrip("/") + write_path
        self.client = httpx.Client(timeout=timeout_sec)
        self._errors_consecutive = 0

    def write(self, lines: list[str]) -> None:
        if not lines:
            return
        payload = "\n".join(lines).encode("utf-8")
        try:
            resp = self.client.post(self.url, content=payload, headers={"Content-Type": "text/plain"})
            resp.raise_for_status()
            if self._errors_consecutive > 0:
                log.info("VictoriaMetrics снова доступна после %d ошибок", self._errors_consecutive)
            self._errors_consecutive = 0
            log.info("✓ VM приняла %d строк (%d байт) → 204 OK", len(lines), len(payload))
        except httpx.HTTPStatusError as exc:
            self._errors_consecutive += 1
            log.error("✗ VM вернула HTTP %s при записи %d строк (ошибка #%d): %s",
                      exc.response.status_code, len(lines), self._errors_consecutive, exc.response.text[:200])
        except Exception as exc:
            self._errors_consecutive += 1
            log.error("✗ ошибка записи в VM (ошибка #%d): %s", self._errors_consecutive, exc)

    def close(self) -> None:
        self.client.close()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    stop = False

    def _handle_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True
        log.info("получен сигнал остановки — завершаем работу")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("=" * 60)
    log.info("NetFlow Collector запускается")
    log.info("  Слушаем UDP: %s:%s", LISTEN_HOST, LISTEN_PORT)
    log.info("  VictoriaMetrics: %s%s", VM_URL, VM_WRITE_PATH)
    log.info("  Уровень лога: %s", LOG_LEVEL)
    log.info("  Template TTL: %ds", TEMPLATE_TTL_SEC)
    log.info("  VLAN if-map:  %s правил", sum(len(m) for m in _IF_VLAN_MAP.values()))
    log.info("  VLAN subnet:  %s подсетей", len(_SUBNET_VLAN_MAP))
    log.info("  Timestamp: локальное время сервера (часы роутера игнорируются)")
    log.info("  Файл таймингов: %s", PROCESSING_TIMES_FILE)
    log.info("  Размер очереди приём→обработка: %d пакетов", PACKET_QUEUE_SIZE)
    log.info("=" * 60)

    cache  = TemplateCache(TEMPLATE_TTL_SEC)
    writer = VictoriaWriter(VM_URL, VM_WRITE_PATH, VM_TIMEOUT_SEC)
    times_writer = ProcessingTimesWriter(PROCESSING_TIMES_FILE)
    sec_filter   = SecurityFilter(ALLOWED_EXPORTERS, RATE_LIMIT_PPS, SECURITY_LOG_VERBOSE)
    seq_tracker  = SequenceTracker(SECURITY_LOG_VERBOSE)
    sec_log.info("контроль sequence number включён (защита от replay)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.settimeout(1.0)
    log.info("UDP сокет открыт — ожидаем пакеты")

    # ── очередь между приёмом и обработкой ────────────────────────────────────
    packet_queue: "queue.Queue[tuple[bytes, tuple[str, int], float]]" = queue.Queue(maxsize=PACKET_QUEUE_SIZE)
    dropped_by_queue = 0  # счётчик вытеснений из-за переполнения

    def receiver_loop() -> None:
        """Только приём пакетов с сокета и фильтрация по безопасности."""
        nonlocal dropped_by_queue
        q_log.info("приёмная нитка запущена")
        while not stop:
            try:
                packet, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            recv_ts = time.time()
            exporter_ip = addr[0]

            # Фильтр безопасности — allowlist и rate-limit.
            if not sec_filter.check(exporter_ip):
                continue

            try:
                packet_queue.put_nowait((packet, addr, recv_ts))
            except queue.Full:
                try:
                    packet_queue.get_nowait()  # выкидываем старый
                    dropped_by_queue += 1
                    if dropped_by_queue == 1 or dropped_by_queue % 100 == 0:
                        q_log.warning("очередь переполнена (размер=%d), вытеснено пакетов: %d",
                                      PACKET_QUEUE_SIZE, dropped_by_queue)
                    packet_queue.put_nowait((packet, addr, recv_ts))
                except queue.Empty:
                    pass
        q_log.info("приёмная нитка остановлена")

    recv_thread = threading.Thread(target=receiver_loop, name="receiver", daemon=True)
    recv_thread.start()

    # ── основной поток: обработка пакетов из очереди ──────────────────────────
    packets_total = 0
    flows_total   = 0
    last_stats_at = time.time()

    try:
        while not stop:
            try:
                packet, addr, recv_ts = packet_queue.get(timeout=1.0)
            except queue.Empty:
                # Каждые 60 секунд выводим статистику даже если нет трафика
                if time.time() - last_stats_at >= 60:
                    log.info("статистика: пакетов=%d флоу=%d очередь=%d (всё время)",
                             packets_total, flows_total, packet_queue.qsize())
                    last_stats_at = time.time()
                continue

            # ── таймер обработки пакета ──────────────────────────────────────
            start_ts = time.time()
            start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat(timespec="milliseconds")
            queue_delay_ms = (start_ts - recv_ts) * 1000
            log.info("▶ старт обработки пакета от %s в %s (задержка в очереди %.2f мс, длина очереди %d)",
                     addr[0], start_iso, queue_delay_ms, packet_queue.qsize())

            try:
                flows = parse_packet(packet, addr, cache, seq_tracker)
                packets_total += 1
                flows_total   += len(flows)

                vm_lines: list[str] = []
                for flow in flows:
                    line = _to_vm_line(flow)
                    if line:
                        vm_lines.append(line)

                writer.write(vm_lines)

                if flows:
                    log.info("пакет от %s: версия=%s флоу=%d → VM строк=%d",
                             addr[0],
                             flows[0].record.get("export_protocol", "?"),
                             len(flows), len(vm_lines))
                    # Показываем каждый флоу детально
                    for i, flow in enumerate(flows):
                        r = flow.record
                        vlan = r.get("vlan_id", "—")
                        src  = r.get("src", "?")
                        dst  = r.get("dst", "?")
                        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
                            r.get("protocol") if isinstance(r.get("protocol"), int)
                            else int(r.get("protocol", 0)), str(r.get("protocol", "?")))
                        sport = r.get("src_port", "?")
                        dport = r.get("dst_port", "?")
                        byt  = r.get("bytes", 0)
                        pkts = r.get("packets", 0)
                        ok   = "✓" if i < len(vm_lines) else "✗ пропущен"
                        log.info("  %s флоу[%d]: vlan=%-5s %s:%s → %s:%s  %s  байт=%-8s пакет=%s",
                                 ok, i + 1, vlan, src, sport, dst, dport, proto, byt, pkts)

                # ── финиш и запись в файл ───────────────────────────────────
                end_ts = time.time()
                end_iso = datetime.fromtimestamp(end_ts, tz=timezone.utc).isoformat(timespec="milliseconds")
                duration_ms = (end_ts - start_ts) * 1000
                log.info("■ финиш обработки пакета от %s в %s — длительность %.2f мс (флоу=%d, vm_строк=%d)",
                         addr[0], end_iso, duration_ms, len(flows), len(vm_lines))
                times_writer.append(start_ts, end_ts, addr[0], len(flows), len(vm_lines))

            except Exception:
                log.exception("ошибка обработки пакета от %s", addr)
                # Даже при ошибке фиксируем тайминг, чтобы видеть аномалии
                end_ts = time.time()
                times_writer.append(start_ts, end_ts, addr[0], 0, 0)

    finally:
        log.info("завершение: всего пакетов=%d флоу=%d (вытеснено очередью=%d)",
                 packets_total, flows_total, dropped_by_queue)
        sock.close()
        recv_thread.join(timeout=2.0)
        writer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())