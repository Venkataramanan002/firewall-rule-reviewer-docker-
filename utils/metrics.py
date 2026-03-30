"""
utils/metrics.py
────────────────
Prometheus metric definitions shared across the entire application.

Metrics exposed:
  • parse_success_total      — Counter  (vendor, log_type)
  • parse_error_total        — Counter  (vendor, log_type, reason)
  • db_insert_duration       — Histogram (table)
  • db_insert_success_total  — Counter  (table)
  • db_insert_errors_total   — Counter  (table)
  • snmp_poll_duration       — Histogram (device, vendor)
  • snmp_poll_errors_total   — Counter  (device, vendor, reason)
  • syslog_messages_received — Counter  (src_ip)
  • redis_cache_hits_total   — Counter
  • redis_cache_misses_total — Counter
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram, start_http_server
import logging
import os

logger = logging.getLogger(__name__)

# ── Parse metrics ─────────────────────────────────────────────────────────────

parse_success_total = Counter(
    "parse_success_total",
    "Number of log messages successfully parsed",
    ["vendor", "log_type"],
)

parse_error_total = Counter(
    "parse_error_total",
    "Number of log messages that failed to parse",
    ["vendor", "log_type", "reason"],
)

# ── Database metrics ──────────────────────────────────────────────────────────

DB_INSERT_DURATION = Histogram(
    "db_insert_duration_seconds",
    "Time spent on a single database INSERT (or batch)",
    ["table"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

db_insert_success_total = Counter(
    "db_insert_success_total",
    "Number of rows successfully inserted",
    ["table"],
)

db_insert_errors_total = Counter(
    "db_insert_errors_total",
    "Number of failed database inserts",
    ["table"],
)

# ── SNMP metrics ──────────────────────────────────────────────────────────────

snmp_poll_duration = Histogram(
    "snmp_poll_duration_seconds",
    "Time to complete one full SNMP poll for a device",
    ["device", "vendor"],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
)

snmp_poll_errors_total = Counter(
    "snmp_poll_errors_total",
    "Number of SNMP poll failures",
    ["device", "vendor", "reason"],
)

# ── Syslog metrics ────────────────────────────────────────────────────────────

syslog_messages_received = Counter(
    "syslog_messages_received_total",
    "Total UDP syslog messages received",
    ["src_ip"],
)

# ── Redis metrics ─────────────────────────────────────────────────────────────

redis_cache_hits_total = Counter(
    "redis_cache_hits_total",
    "Number of deduplication cache hits (duplicate logs skipped)",
)

redis_cache_misses_total = Counter(
    "redis_cache_misses_total",
    "Number of deduplication cache misses (new logs processed)",
)


# ── HTTP server ───────────────────────────────────────────────────────────────

def start_metrics_server() -> None:
    """
    Start the Prometheus HTTP metrics server.
    Port is read from METRICS_PORT env var (default 9090).
    """
    port = int(os.environ.get("METRICS_PORT", "9090"))
    try:
        start_http_server(port)
        logger.info("Prometheus metrics server started", extra={"port": port})
    except OSError as exc:
        logger.error("Could not start metrics server: %s", exc)
