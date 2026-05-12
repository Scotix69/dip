"""
metrics-api — HTTP API поверх VictoriaMetrics.

Что делает:
  Сам по себе данные НЕ собирает и НЕ хранит.
  По запросу идёт в VictoriaMetrics, делает PromQL-запросы,
  агрегирует байты/пакеты/флоу по VLAN за указанный период
  и возвращает результат клиенту в нужном формате.

Endpoints:
  GET /health                  — проверка работоспособности
  GET /tables/vlans            — JSON: метрики по каждому VLAN
  GET /tables/vlans.csv        — CSV: то же самое для Excel/таблиц
  GET /events/metrics_event    — JSON-events для внешних систем

Авторизация: HTTP Basic Auth (API_USER / API_PASSWORD).
"""
import csv
import io
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import Query, Request, Response
from pydantic import BaseModel

# ── конфигурация ──────────────────────────────────────────────────────────────
VM_URL                   = os.getenv("VM_URL", "http://victoriametrics:8428").rstrip("/")
AGG_PERIOD_SEC           = int(os.getenv("AGG_PERIOD_SEC", "60"))
DEFAULT_LINK_CAPACITY_BPS = float(os.getenv("DEFAULT_LINK_CAPACITY_BPS", "100000000"))
LOG_LEVEL                = os.getenv("LOG_LEVEL", "INFO").upper()

# ── логирование ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)-8s [metrics-api] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("metrics-api")

app = FastAPI(
    title="AVLAN Metrics API",
    version="0.4.0",
    description=__doc__,
)


# ── middleware: логируем каждый запрос ────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed_ms = (time.time() - start) * 1000
    log.info("%s %s → %d  (%.1f мс)", request.method, request.url.path, response.status_code, elapsed_ms)
    return response


# ── startup лог ───────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    log.info("=" * 60)
    log.info("Metrics API запускается")
    log.info("  VictoriaMetrics: %s", VM_URL)
    log.info("  Период агрегации: %d сек", AGG_PERIOD_SEC)
    log.info("  Ёмкость канала: %.0f bps (%.0f Mbit/s)", DEFAULT_LINK_CAPACITY_BPS, DEFAULT_LINK_CAPACITY_BPS / 1e6)
    log.info("=" * 60)
    # Проверяем доступность VM при старте
    try:
        resp = httpx.get(f"{VM_URL}/health", timeout=5.0)
        resp.raise_for_status()
        log.info("VictoriaMetrics доступна: %s", VM_URL)
    except Exception as exc:
        log.warning("VictoriaMetrics недоступна при старте: %s — API будет работать, но запросы могут падать", exc)


# ── модели ────────────────────────────────────────────────────────────────────
class VlanMetricRow(BaseModel):
    vlan_id: int
    period_sec: int
    bytes_in: float
    packets_in: float
    bytes_per_sec: float
    packets_per_sec: float
    flow_count: int
    anomaly_score: float
    utilization: float
    timestamp: str


# ── запросы в VictoriaMetrics ─────────────────────────────────────────────────
def _vm_query(query: str) -> list[dict[str, Any]]:
    """Выполняет instant query в VictoriaMetrics и возвращает список результатов."""
    log.debug("VM запрос: %s", query)
    try:
        resp = httpx.get(f"{VM_URL}/api/v1/query", params={"query": query}, timeout=10.0)
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        log.error("VM вернула HTTP %s на запрос: %s", exc.response.status_code, query[:120])
        raise RuntimeError(f"VM HTTP {exc.response.status_code}") from exc
    except Exception as exc:
        log.error("ошибка запроса к VM: %s — query: %s", exc, query[:120])
        raise
    data = resp.json()
    if data.get("status") != "success":
        log.error("VM вернула status!=success: %s", data)
        raise RuntimeError(data)
    results = data.get("data", {}).get("result", [])
    log.debug("VM ответ: %d временных рядов", len(results))
    return results


def _value_by_vlan(query: str) -> dict[int, float]:
    """Из результатов VM извлекает словарь {vlan_id: значение}."""
    vlan_label_priority = (
        "vlan_id", "vlan_src", "dot1q_vlan_id", "dot1q_customer_vlan_id",
        "post_vlan_id", "vlan_dst", "post_dot1q_vlan_id",
        "post_dot1q_customer_vlan_id", "vlan", "input_if", "output_if",
    )
    result: dict[int, float] = {}
    for item in _vm_query(query):
        metric = item.get("metric", {})
        vlan_raw = "0"
        for label in vlan_label_priority:
            if metric.get(label):
                vlan_raw = metric[label]
                break
        try:
            vlan_id = int(float(vlan_raw))
        except ValueError:
            continue
        result[vlan_id] = float(item.get("value", [None, 0])[1])
    return result


def _sum_over_time_by_label(metric_regex: str, label: str, period_sec: int, extra_matchers: str = "") -> dict[int, float]:
    matchers = f'__name__=~"{metric_regex}",{label}=~".+"'
    if extra_matchers:
        matchers = f"{matchers},{extra_matchers}"
    return _value_by_vlan(f"sum(sum_over_time({{{matchers}}}[{period_sec}s])) by ({label})")


def _sum_flow_metric(metric_regex: str, period_sec: int) -> dict[int, float]:
    """Суммирует метрику по всем возможным VLAN-лейблам без дублирования."""
    return _merge_values(
        _sum_over_time_by_label(metric_regex, "vlan_id", period_sec),
        _sum_over_time_by_label(metric_regex, "vlan_src", period_sec, 'vlan_id=""'),
        _sum_over_time_by_label(metric_regex, "dot1q_vlan_id", period_sec, 'vlan_id="",vlan_src=""'),
        _sum_over_time_by_label(metric_regex, "dot1q_customer_vlan_id", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id=""'),
        _sum_over_time_by_label(metric_regex, "post_vlan_id", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id="",dot1q_customer_vlan_id=""'),
        _sum_over_time_by_label(metric_regex, "vlan_dst", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id="",dot1q_customer_vlan_id="",post_vlan_id=""'),
        _sum_over_time_by_label(metric_regex, "post_dot1q_vlan_id", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id="",dot1q_customer_vlan_id="",post_vlan_id="",vlan_dst=""'),
        _sum_over_time_by_label(metric_regex, "post_dot1q_customer_vlan_id", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id="",dot1q_customer_vlan_id="",post_vlan_id="",vlan_dst="",post_dot1q_vlan_id=""'),
        _sum_over_time_by_label(metric_regex, "input_if", period_sec, 'vlan_id="",vlan_src="",dot1q_vlan_id="",dot1q_customer_vlan_id="",post_vlan_id="",vlan_dst="",post_dot1q_vlan_id="",post_dot1q_customer_vlan_id=""'),
    )


def _merge_values(*parts: dict[int, float]) -> dict[int, float]:
    merged: dict[int, float] = {}
    for part in parts:
        for vlan_id, value in part.items():
            merged[vlan_id] = merged.get(vlan_id, 0.0) + value
    return merged


def build_rows(period_sec: int = AGG_PERIOD_SEC, capacity_bps: float = DEFAULT_LINK_CAPACITY_BPS) -> list[VlanMetricRow]:
    """Основная функция: агрегирует данные из VM и строит строки по VLAN."""
    t0 = time.time()
    log.info("агрегация данных: period=%ds capacity=%.0f bps", period_sec, capacity_bps)

    bytes_metric   = r"netflow_(in_bytes|in_total_bytes|bytes|octetDeltaCount|test_bytes_in)"
    packets_metric = r"netflow_(in_packets|in_total_packets|packets|packetDeltaCount|test_packets_in)"
    flows_metric   = r"netflow_(flow_count|test_flow_count)"

    bytes_by_vlan   = _sum_flow_metric(bytes_metric,   period_sec)
    packets_by_vlan = _sum_flow_metric(packets_metric, period_sec)
    flows_by_vlan   = _sum_flow_metric(flows_metric,   period_sec)

    all_vlans = sorted(set(bytes_by_vlan) | set(packets_by_vlan) | set(flows_by_vlan))
    log.info("найдено VLAN: %d (за %.1f мс)", len(all_vlans), (time.time() - t0) * 1000)

    now  = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rows: list[VlanMetricRow] = []
    for vlan_id in all_vlans:
        bytes_in        = bytes_by_vlan.get(vlan_id, 0.0)
        packets_in      = packets_by_vlan.get(vlan_id, 0.0)
        bytes_per_sec   = bytes_in / period_sec
        packets_per_sec = packets_in / period_sec
        utilization     = min((bytes_per_sec * 8) / capacity_bps, 1.0) if capacity_bps > 0 else 0.0
        anomaly_score   = round((utilization * 4.0) + min(flows_by_vlan.get(vlan_id, 0.0) / 100.0, 2.0), 3)
        rows.append(VlanMetricRow(
            vlan_id=vlan_id,
            period_sec=period_sec,
            bytes_in=round(bytes_in, 3),
            packets_in=round(packets_in, 3),
            bytes_per_sec=round(bytes_per_sec, 3),
            packets_per_sec=round(packets_per_sec, 3),
            flow_count=int(flows_by_vlan.get(vlan_id, 0)),
            anomaly_score=anomaly_score,
            utilization=round(utilization, 5),
            timestamp=now,
        ))
    return rows


def to_metrics_event(row: VlanMetricRow) -> dict[str, Any]:
    return {
        "type": "metrics_event",
        "timestamp": row.timestamp,
        "source": "metrics-api",
        "payload": {
            "vlan_id": row.vlan_id,
            "period_sec": row.period_sec,
            "bytes_in": row.bytes_in,
            "bytes_out": 0,
            "packets_in": row.packets_in,
            "packets_out": 0,
            "bytes_per_sec": row.bytes_per_sec,
            "packets_per_sec": row.packets_per_sec,
            "flow_count": row.flow_count,
            "anomaly_score": row.anomaly_score,
            "utilization": row.utilization,
            "top_talkers": [],
        },
    }


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tables/vlans", response_model=list[VlanMetricRow])
def vlan_table(period_sec: int = Query(default=AGG_PERIOD_SEC, ge=10, le=3600)) -> list[VlanMetricRow]:
    """JSON: метрики по каждому VLAN за последние period_sec секунд."""
    return build_rows(period_sec=period_sec)


@app.get("/tables/vlans.csv")
def vlan_table_csv(period_sec: int = Query(default=AGG_PERIOD_SEC, ge=10, le=3600)) -> Response:
    """CSV: то же что /tables/vlans, удобно для Excel."""
    rows = build_rows(period_sec=period_sec)
    buf  = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(VlanMetricRow.model_fields.keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow(row.model_dump())
    log.info("CSV сформирован: %d строк", len(rows))
    return Response(content=buf.getvalue(), media_type="text/csv")


@app.get("/events/metrics_event")
def metrics_events(period_sec: int = Query(default=AGG_PERIOD_SEC, ge=10, le=3600)) -> list[dict[str, Any]]:
    """JSON-events: для внешних систем (decision-engine и др.)."""
    rows = build_rows(period_sec=period_sec)
    log.info("events сформированы: %d событий", len(rows))
    return [to_metrics_event(row) for row in rows]
