#!/usr/bin/env python3
"""
check_pipeline.py — сквозная диагностика NetFlow-коллектора.

Что делает:
  1. Отправляет тестовые пакеты NetFlow v5 / v9 / IPFIX на коллектор.
  2. Ждёт, пока они пройдут через коллектор и осядут в VictoriaMetrics.
  3. Спрашивает VictoriaMetrics: появились ли метрики нужных протоколов.
  4. Печатает итоговую таблицу: PASS / FAIL / WARN по каждой проверке.

Запуск (когда docker compose up уже сделан):
  python3 tests/check_pipeline.py

Переменные окружения (всё необязательно, показаны дефолты):
  COLLECTOR_HOST      127.0.0.1
  COLLECTOR_PORT      2055
  VM_URL              http://localhost:8428
  WAIT_SEC            4        # сколько ждать после отправки пакетов
  CHECK_SRC_V5        10.99.5.1
  CHECK_SRC_V9        10.99.9.2
  CHECK_SRC_IPFIX     10.99.10.3
  TEST_VLAN           42
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── конфигурация ─────────────────────────────────────────────────────────────

COLLECTOR_HOST  = os.getenv("COLLECTOR_HOST",  "127.0.0.1")
COLLECTOR_PORT  = int(os.getenv("COLLECTOR_PORT", "2055"))
VM_URL          = os.getenv("VM_URL",          "http://localhost:8428").rstrip("/")
WAIT_SEC        = float(os.getenv("WAIT_SEC", "4"))

# Уникальные src-IP для каждого протокола — по ним ищем в хранилищах
SRC_V5    = os.getenv("CHECK_SRC_V5",    "10.99.5.1")
SRC_V9    = os.getenv("CHECK_SRC_V9",    "10.99.9.2")
SRC_IPFIX = os.getenv("CHECK_SRC_IPFIX", "10.99.10.3")
DST       = "10.99.0.254"
TEST_VLAN = int(os.getenv("TEST_VLAN", "42"))

# ── цвета ─────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"

def green(s: str)  -> str: return f"{GREEN}{s}{RESET}"
def red(s: str)    -> str: return f"{RED}{s}{RESET}"
def yellow(s: str) -> str: return f"{YELLOW}{s}{RESET}"
def cyan(s: str)   -> str: return f"{CYAN}{s}{RESET}"
def bold(s: str)   -> str: return f"{BOLD}{s}{RESET}"

# ── результат одной проверки ──────────────────────────────────────────────────

@dataclass
class Check:
    name:   str
    status: str = "SKIP"   # PASS | FAIL | WARN | SKIP
    detail: str = ""
    extra:  list[str] = field(default_factory=list)

    def mark(self, ok: bool, pass_msg: str = "", fail_msg: str = "") -> "Check":
        self.status = "PASS" if ok else "FAIL"
        self.detail = pass_msg if ok else fail_msg
        return self

    def warn(self, msg: str) -> "Check":
        self.status = "WARN"
        self.detail = msg
        return self

    def colored(self) -> str:
        s = self.status
        if s == "PASS": return green(f"[PASS]")
        if s == "FAIL": return red(f"[FAIL]")
        if s == "WARN": return yellow(f"[WARN]")
        return f"[{s}]"

# ── построение пакетов ────────────────────────────────────────────────────────

def _ip(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def build_v5(src: str, dst: str, input_if: int = 3, bytes_n: int = 60_000, pkts: int = 400) -> bytes:
    now = int(time.time())
    header = struct.pack("!HHIIIIBBH", 5, 1, 0, now, 0, 1, 0, 0, 0)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        _ip(src), _ip(dst), 0,
        input_if, input_if,
        pkts, bytes_n,
        0, 0,
        12345, 443,
        0, 0,          # pad1, pad2
        6, 0, 0,       # tcp_flags, protocol=TCP, tos
        0, 0, 24, 0,   # src_as, dst_as, src_mask, dst_mask
    )
    return header + record


def build_v9(src: str, dst: str, vlan: int, bytes_n: int = 60_000, pkts: int = 400) -> tuple[bytes, bytes]:
    now = int(time.time())
    source_id = 100
    tid = 256
    # fields: src(8,4) dst(12,4) sport(7,2) dport(11,2) proto(4,1) vlan(58,2) bytes(1,4) pkts(2,4)
    flds = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (58, 2), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", tid, len(flds)) + b"".join(struct.pack("!HH", t, l) for t, l in flds)
    tpl_set  = struct.pack("!HH", 0, 4 + len(tpl_body)) + tpl_body
    tpl_pkt  = struct.pack("!HHIIII", 9, 1, 0, now, 1, source_id) + tpl_set

    data_body = struct.pack("!IIHHBHII", _ip(src), _ip(dst), 12345, 443, 6, vlan, bytes_n, pkts)
    data_set  = struct.pack("!HH", tid, 4 + len(data_body)) + data_body
    data_pkt  = struct.pack("!HHIIII", 9, 1, 0, now, 2, source_id) + data_set
    return tpl_pkt, data_pkt


def build_ipfix(src: str, dst: str, vlan: int, bytes_n: int = 60_000, pkts: int = 400) -> tuple[bytes, bytes]:
    now = int(time.time())
    domain_id = 200
    tid = 256
    flds = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (58, 2), (1, 4), (2, 4)]
    tpl_body = struct.pack("!HH", tid, len(flds)) + b"".join(struct.pack("!HH", t, l) for t, l in flds)
    tpl_set  = struct.pack("!HH", 2, 4 + len(tpl_body)) + tpl_body
    tpl_len  = 16 + len(tpl_set)
    tpl_pkt  = struct.pack("!HHIII", 10, tpl_len, now, 1, domain_id) + tpl_set

    data_body = struct.pack("!IIHHBHII", _ip(src), _ip(dst), 12345, 443, 6, vlan, bytes_n, pkts)
    data_set  = struct.pack("!HH", tid, 4 + len(data_body)) + data_body
    data_len  = 16 + len(data_set)
    data_pkt  = struct.pack("!HHIII", 10, data_len, now, 2, domain_id) + data_set
    return tpl_pkt, data_pkt

# ── отправка ──────────────────────────────────────────────────────────────────

def send_all() -> list[Check]:
    checks: list[Check] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # v5
        c = Check("Отправка NetFlow v5")
        try:
            sock.sendto(build_v5(SRC_V5, DST, input_if=3), (COLLECTOR_HOST, COLLECTOR_PORT))
            c.mark(True, f"src={SRC_V5}  if=3  → коллектор {COLLECTOR_HOST}:{COLLECTOR_PORT}")
        except OSError as e:
            c.mark(False, fail_msg=str(e))
        checks.append(c)

        # v9
        c = Check("Отправка NetFlow v9")
        try:
            tpl, data = build_v9(SRC_V9, DST, TEST_VLAN)
            sock.sendto(tpl,  (COLLECTOR_HOST, COLLECTOR_PORT))
            time.sleep(0.05)
            sock.sendto(data, (COLLECTOR_HOST, COLLECTOR_PORT))
            c.mark(True, f"src={SRC_V9}  vlan={TEST_VLAN}  template+data")
        except OSError as e:
            c.mark(False, fail_msg=str(e))
        checks.append(c)

        # IPFIX
        c = Check("Отправка IPFIX")
        try:
            tpl, data = build_ipfix(SRC_IPFIX, DST, TEST_VLAN)
            sock.sendto(tpl,  (COLLECTOR_HOST, COLLECTOR_PORT))
            time.sleep(0.05)
            sock.sendto(data, (COLLECTOR_HOST, COLLECTOR_PORT))
            c.mark(True, f"src={SRC_IPFIX}  vlan={TEST_VLAN}  template+data")
        except OSError as e:
            c.mark(False, fail_msg=str(e))
        checks.append(c)

    finally:
        sock.close()
    return checks

# ── VictoriaMetrics ───────────────────────────────────────────────────────────

def vm_query(query: str, lookback: str = "2m") -> dict[str, Any] | None:
    url = f"{VM_URL}/api/v1/query?query={urllib.parse.quote(query)}&time=now&step={lookback}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.load(r)
    except urllib.error.URLError as e:
        return None
    except Exception:
        return None


def vm_discover_netflow_metric() -> str | None:
    """
    VictoriaMetrics принимает данные в формате InfluxDB line protocol.
    Measurement 'netflow' + field 'bytes' → метрика 'netflow_bytes'.
    Measurement 'netflow' + field 'flow_count' → 'netflow_flow_count'.

    Эта функция находит реальное имя метрики через /api/v1/label/__name__/values
    и возвращает первое совпадение вида 'netflow_*', либо None.
    """
    url = f"{VM_URL}/api/v1/label/__name__/values"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.load(r)
        names: list[str] = data.get("data", [])
        # Предпочитаем netflow_flow_count, потом netflow_bytes, потом любой netflow_*
        for preferred in ("netflow_flow_count", "netflow_bytes", "netflow_packets"):
            if preferred in names:
                return preferred
        for name in names:
            if name.startswith("netflow_") or name == "netflow":
                return name
        return None
    except Exception:
        return None


def check_vm() -> list[Check]:
    checks: list[Check] = []

    # 1. Доступность
    c = Check("VictoriaMetrics: доступность")
    try:
        urllib.request.urlopen(f"{VM_URL}/health", timeout=3)
        c.mark(True, f"{VM_URL} отвечает")
    except Exception as e:
        c.mark(False, fail_msg=f"Не удалось подключиться к {VM_URL}: {e}")
    checks.append(c)
    if c.status == "FAIL":
        return checks

    # 2. Обнаружение реального имени метрики
    c = Check("VictoriaMetrics: обнаружение метрики netflow_*")
    metric_name = vm_discover_netflow_metric()
    if metric_name:
        c.mark(True, f"найдена метрика «{metric_name}»")
        c.extra = [f"  ℹ️  VM хранит данные как {{measurement}}_{{field}}, "
                   f"т.е. 'netflow' + 'flow_count' = '{metric_name}'"]
    else:
        c.mark(False, fail_msg="метрик вида netflow_* не найдено в VM — коллектор не пишет данные")
        c.extra = [
            "  Проверь:",
            f"  • docker compose logs netflow-collector  (ищи ошибки записи в VM)",
            f"  • curl -s {VM_URL}/api/v1/label/__name__/values | python3 -m json.tool",
        ]
    checks.append(c)
    if metric_name is None:
        return checks

    def find_src(proto_label: str, src_ip: str) -> tuple[bool, str]:
        q = f'{metric_name}{{export_protocol="{proto_label}",src="{src_ip}"}}'
        res = vm_query(q)
        if res is None:
            return False, "ошибка запроса к VM"
        results = res.get("data", {}).get("result", [])
        if not results:
            # Попробуем без src — может быть src не попал в теги
            q2 = f'{metric_name}{{export_protocol="{proto_label}"}}'
            res2 = vm_query(q2)
            r2 = res2.get("data", {}).get("result", []) if res2 else []
            if r2:
                sample_tags = r2[0].get("metric", {})
                return False, (
                    f"протокол {proto_label} ЕСТЬ в VM, но src={src_ip} не найден.\n"
                    f"          Реальные теги: {sample_tags}\n"
                    f"          Возможно src попал в поля, а не в теги — проверь TAG_KEYS в collector.py"
                )
            return False, f"нет данных (query: {q})"
        last = results[0]
        val  = last.get("value", [None, "?"])[1]
        tags = {k: v for k, v in last.get("metric", {}).items() if k != "__name__"}
        return True, f"value={val}  labels={tags}"

    # 3–5. Наличие флоу каждого протокола
    for proto_label, src in [
        ("netflow_v5",  SRC_V5),
        ("netflow_v9",  SRC_V9),
        ("ipfix",       SRC_IPFIX),
    ]:
        c = Check(f"VictoriaMetrics: {proto_label}  src={src}")
        ok, detail = find_src(proto_label, src)
        c.mark(ok, pass_msg=detail, fail_msg=detail)
        checks.append(c)

    # 6. Проверка vlan_id тега (v9 / IPFIX)
    c = Check(f"VictoriaMetrics: vlan_id={TEST_VLAN} присутствует")
    q = f'{metric_name}{{vlan_id="{TEST_VLAN}"}}'
    res = vm_query(q)
    if res is None:
        c.warn("ошибка запроса к VM")
    else:
        results = res.get("data", {}).get("result", [])
        c.mark(
            bool(results),
            pass_msg=f"найдено {len(results)} временных рядов с vlan_id={TEST_VLAN}",
            fail_msg=f"нет метрик с vlan_id={TEST_VLAN}  (query: {q})",
        )
    checks.append(c)

    # 7. Показываем полный список лейблов — полезно для дашбордов
    c = Check("VictoriaMetrics: доступные лейблы метрики")
    url = f"{VM_URL}/api/v1/labels"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            ldata = json.load(r)
        all_labels = [l for l in ldata.get("data", []) if l != "__name__"]
        c.mark(True, f"всего лейблов: {len(all_labels)}")
        c.extra = [f"  {all_labels}"]
    except Exception as e:
        c.warn(str(e))
    checks.append(c)

    return checks

# ── итоговый вывод ────────────────────────────────────────────────────────────

def print_summary(all_checks: dict[str, list[Check]]) -> int:
    total = pass_ = fail = warn = 0
    print()
    print(bold("═" * 66))
    print(bold("  ИТОГ ДИАГНОСТИКИ PIPELINE"))
    print(bold("═" * 66))

    for section, checks in all_checks.items():
        print(f"\n{cyan(bold(section))}")
        for ch in checks:
            icon = ch.colored()
            print(f"  {icon}  {ch.name}")
            if ch.detail:
                print(f"          {ch.detail}")
            for line in ch.extra:
                print(line)
            total += 1
            if ch.status == "PASS": pass_ += 1
            elif ch.status == "FAIL": fail += 1
            elif ch.status == "WARN": warn += 1

    print()
    print(bold("─" * 66))
    summary = f"  Всего: {total}  |  {green(f'PASS: {pass_}')}  |  {red(f'FAIL: {fail}')}  |  {yellow(f'WARN: {warn}')}"
    print(summary)
    print(bold("─" * 66))

    if fail == 0 and warn == 0:
        print(green(bold("  ✅  Все проверки прошли успешно!")))
    elif fail == 0:
        print(yellow(bold(f"  ⚠️   Пройдено с предупреждениями ({warn}). Проверь WARN-пункты.")))
    else:
        print(red(bold(f"  ❌  {fail} проверок не прошло. Смотри FAIL-пункты выше.")))
        print()
        print("  Частые причины FAIL:")
        print("    • docker compose up ещё не запущен")
        print("    • коллектор не получил пакеты (firewall / неверный порт)")
        print("    • WAIT_SEC слишком мало — данные не успели дойти (попробуй WAIT_SEC=8)")
        print("    • VictoriaMetrics упала (docker compose ps)")
    print()
    return 1 if fail else 0

# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print(bold(f"\n{'─'*66}"))
    print(bold("  NetFlow Pipeline Diagnostics"))
    print(bold(f"{'─'*66}"))
    print(f"  Коллектор : {COLLECTOR_HOST}:{COLLECTOR_PORT}/udp")
    print(f"  Victoria  : {VM_URL}")
    print(f"  Ожидание  : {WAIT_SEC}с  |  TEST_VLAN={TEST_VLAN}")
    print(f"  Src IP    : v5={SRC_V5}  v9={SRC_V9}  ipfix={SRC_IPFIX}")
    print()

    # ── 1. Отправляем пакеты ──
    print(cyan("▶ Отправка тестовых пакетов…"))
    send_checks = send_all()
    for c in send_checks:
        print(f"  {c.colored()}  {c.name}  —  {c.detail}")

    send_ok = all(c.status == "PASS" for c in send_checks)
    if not send_ok:
        print(red("\n  Не удалось отправить пакеты. Дальнейшие проверки могут быть бессмысленны."))

    # ── 2. Ждём ──
    print(f"\n{cyan(f'⏳ Ожидаем {WAIT_SEC}с пока коллектор обработает флоу…')}")
    for i in range(int(WAIT_SEC)):
        time.sleep(1)
        print(f"  {i+1}/{int(WAIT_SEC)}…", end="\r", flush=True)
    print()

    # ── 3. Проверяем Victoria ──
    print(cyan("\n▶ Проверяем VictoriaMetrics…"))
    vm_checks = check_vm()

    # ── 4. Сводка ──
    return print_summary({
        "📤 Отправка пакетов":         send_checks,
        "📊 VictoriaMetrics":          vm_checks,
    })


if __name__ == "__main__":
    sys.exit(main())
