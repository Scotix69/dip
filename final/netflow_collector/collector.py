import ipaddress
import json
import logging
import os
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
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

# ── логирование ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)-8s [collector] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("netflow-collector")

# ── VLAN enrichment для NetFlow v5 ────────────────────────────────────────────
# NetFlow v5 не содержит VLAN ID. Коллектор поддерживает два способа обогащения:
#
# Способ 1 — V5_VLAN_IF_MAP: SNMP-индекс интерфейса → VLAN ID
#   Формат JSON: {"<ip_экспортёра>": {"<snmp_index>": <vlan_id>}, "*": {"<snmp_index>": <vlan_id>}}
#   Пример: V5_VLAN_IF_MAP={"192.168.1.1":{"3":100,"4":200},"*":{"5":999}}
#   "*" — wildcard, совпадает с любым экспортёром.
#   Узнать индексы: "show snmp mib ifmib ifindex" на Cisco.
#
# Способ 2 — V5_VLAN_SUBNET_MAP: IP-подсеть → VLAN ID (longest-prefix match)
#   Формат JSON: {"<cidr>": <vlan_id>}
#   Пример: V5_VLAN_SUBNET_MAP={"192.168.10.0/24":10,"192.168.20.0/24":20}
#   Сначала проверяется src IP, затем dst IP.

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
        self._templates[(protocol, exporter, domain_id, template_id)] = Template(protocol, fields, record_len, time.time())
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
    for key in ("flow_end_msec", "observation_time_msec", "flow_start_msec"):
        value = record.get(key)
        if isinstance(value, int) and value > 0:
            return value * 1_000_000
    for key in ("flow_end_usec", "flow_start_usec"):
        value = record.get(key)
        if isinstance(value, int) and value > 0:
            return value * 1_000
    for key in ("flow_end_nsec", "flow_start_nsec"):
        value = record.get(key)
        if isinstance(value, int) and value > 0:
            return value
    return fallback_ns


def _to_vm_line(flow: ParsedFlow) -> str | None:
    """Формирует строку InfluxDB line protocol для записи в VictoriaMetrics."""
    record = dict(flow.record)
    _normalize_vlan(record)
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


def _parse_v9(packet: bytes, exporter: str, timestamp_ns: int, cache: TemplateCache) -> list[ParsedFlow]:
    if len(packet) < 20:
        log.warning("слишком короткий v9 пакет от %s: %d байт", exporter, len(packet))
        return []
    version, _count, _uptime, unix_secs, _seq, source_id = struct.unpack("!HHIIII", packet[:20])
    if version != 9:
        return []
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


def _parse_ipfix(packet: bytes, exporter: str, timestamp_ns: int, cache: TemplateCache) -> list[ParsedFlow]:
    if len(packet) < 16:
        log.warning("слишком короткий IPFIX пакет от %s: %d байт", exporter, len(packet))
        return []
    version, total_length, export_time, _seq, domain_id = struct.unpack("!HHIII", packet[:16])
    if version != 10 or total_length < 16 or total_length > len(packet):
        return []
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


def parse_packet(packet: bytes, addr: tuple[str, int], cache: TemplateCache) -> list[ParsedFlow]:
    if len(packet) < 2:
        return []
    version = struct.unpack("!H", packet[:2])[0]
    timestamp_ns = time.time_ns()
    exporter = addr[0]
    if version == 5:
        return _parse_v5(packet, exporter, timestamp_ns)
    if version == 9:
        return _parse_v9(packet, exporter, timestamp_ns, cache)
    if version == 10:
        return _parse_ipfix(packet, exporter, timestamp_ns, cache)
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
            log.debug("→ VM: отправлено %d строк (%d байт)", len(lines), len(payload))
        except httpx.HTTPStatusError as exc:
            self._errors_consecutive += 1
            log.error("VM вернула HTTP %s при записи %d строк (ошибка #%d): %s",
                      exc.response.status_code, len(lines), self._errors_consecutive, exc.response.text[:200])
        except Exception as exc:
            self._errors_consecutive += 1
            log.error("ошибка записи в VM (ошибка #%d): %s", self._errors_consecutive, exc)

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
    log.info("=" * 60)

    cache  = TemplateCache(TEMPLATE_TTL_SEC)
    writer = VictoriaWriter(VM_URL, VM_WRITE_PATH, VM_TIMEOUT_SEC)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.settimeout(1.0)
    log.info("UDP сокет открыт — ожидаем пакеты")

    packets_total = 0
    flows_total   = 0
    last_stats_at = time.time()

    try:
        while not stop:
            try:
                packet, addr = sock.recvfrom(65535)
            except socket.timeout:
                # Каждые 60 секунд выводим статистику даже если нет трафика
                if time.time() - last_stats_at >= 60:
                    log.info("статистика: пакетов=%d флоу=%d (за всё время работы)", packets_total, flows_total)
                    last_stats_at = time.time()
                continue
            except OSError:
                break

            try:
                flows = parse_packet(packet, addr, cache)
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

            except Exception:
                log.exception("ошибка обработки пакета от %s", addr)

    finally:
        log.info("завершение: всего пакетов=%d флоу=%d", packets_total, flows_total)
        sock.close()
        writer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
