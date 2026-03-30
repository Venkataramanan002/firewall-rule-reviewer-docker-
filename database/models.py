"""
Database models — compatible with both SQLite (dev/default) and PostgreSQL (production).

SQLite-safe column types are used throughout. JSON columns use SQLAlchemy's
built-in JSON type which maps to TEXT on SQLite and JSONB on PostgreSQL.
UUID primary keys are stored as String(36) on SQLite, UUID on PostgreSQL.
"""

import os
import uuid
import datetime

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, BigInteger,
    Text, ForeignKey, Numeric, Boolean, JSON
)
from sqlalchemy.orm import declarative_base, relationship

# ---------------------------------------------------------------------------
# Detect dialect so we can use native PG types in production
# ---------------------------------------------------------------------------
# UUID, IP, CIDR columns — identical for both SQLite and PostgreSQL
# Using String types avoids dialect-specific binding issues (asyncpg UUID objects)
def _uuid_col(pk=False, fk=None):
    if pk:
        return Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    if fk:
        return Column(String(36), ForeignKey(fk), nullable=True)
    return Column(String(36), nullable=True)

def _inet_col():
    return Column(String(45), nullable=True)

def _cidr_col():
    return Column(String(50), nullable=True)

Base = declarative_base()


# ---------------------------------------------------------------------------
# Connection log
# ---------------------------------------------------------------------------
class Connection(Base):
    __tablename__ = 'connections'

    id               = _uuid_col(pk=True)
    timestamp        = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    session_end      = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    src_ip           = Column(String(45), index=True, nullable=False)
    dst_ip           = Column(String(45), index=True, nullable=False)
    src_port         = Column(Integer, nullable=False)
    dst_port         = Column(Integer, nullable=False)
    protocol         = Column(String(10), nullable=False)

    bytes_sent       = Column(BigInteger, default=0, nullable=False)
    bytes_received   = Column(BigInteger, default=0, nullable=False)
    packets_sent     = Column(BigInteger, default=0, nullable=False)
    packets_received = Column(BigInteger, default=0, nullable=False)
    tcp_flags        = Column(String(50), nullable=True)

    rule_id          = Column(String(100), nullable=True)
    action           = Column(String(20), nullable=False)
    interface_in     = Column(String(50), nullable=True)
    interface_out    = Column(String(50), nullable=True)
    zone_from        = Column(String(50), nullable=True)
    zone_to          = Column(String(50), nullable=True)

    app_name         = Column(String(100), nullable=True)
    app_category     = Column(String(100), nullable=True)
    url              = Column(Text, nullable=True)
    domain           = Column(String(255), nullable=True)
    user_agent       = Column(Text, nullable=True)
    http_method      = Column(String(10), nullable=True)

    username         = Column(String(100), nullable=True)
    device_name      = Column(String(100), nullable=True)
    device_mac       = Column(String(17), nullable=True)
    device_os        = Column(String(50), nullable=True)

    geo_src_country  = Column(String(100), nullable=True)
    geo_src_city     = Column(String(100), nullable=True)
    geo_dst_country  = Column(String(100), nullable=True)
    geo_dst_city     = Column(String(100), nullable=True)

    nat_src_ip       = Column(String(45), nullable=True)
    nat_src_port     = Column(Integer, nullable=True)
    nat_dst_ip       = Column(String(45), nullable=True)
    nat_dst_port     = Column(Integer, nullable=True)

    decryption_status = Column(String(20), nullable=True)
    threat_detected   = Column(Boolean, default=False, nullable=False)


# ---------------------------------------------------------------------------
# Threat log
# ---------------------------------------------------------------------------
class Threat(Base):
    __tablename__ = 'threats'

    id          = _uuid_col(pk=True)
    timestamp   = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name = Column(String(100), nullable=True)
    src_ip      = Column(String(45), nullable=False)
    dst_ip      = Column(String(45), nullable=False)

    threat_type = Column(String(50), nullable=False)
    threat_name = Column(String(255), nullable=False)
    severity    = Column(String(20), nullable=False)
    risk_score  = Column(Integer, nullable=True)

    file_name   = Column(String(255), nullable=True)
    file_size   = Column(BigInteger, nullable=True)
    file_type   = Column(String(50), nullable=True)
    file_hash   = Column(String(128), nullable=True)


# ---------------------------------------------------------------------------
# System health metrics
# ---------------------------------------------------------------------------
class SystemHealth(Base):
    __tablename__ = 'system_health'

    id                   = _uuid_col(pk=True)
    timestamp            = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name          = Column(String(100), nullable=False)

    cpu_usage_percent    = Column(Float, nullable=False)
    memory_usage_percent = Column(Float, nullable=False)
    active_sessions      = Column(Integer, nullable=False)

    interface_status     = Column(String(20), nullable=True)
    link_speed_mbps      = Column(Integer, nullable=True)
    errors_in            = Column(BigInteger, default=0, nullable=False)
    errors_out           = Column(BigInteger, default=0, nullable=False)


# ---------------------------------------------------------------------------
# Admin audit trail
# ---------------------------------------------------------------------------
class AdminAudit(Base):
    __tablename__ = 'admin_audit'

    id            = _uuid_col(pk=True)
    timestamp     = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name   = Column(String(100), nullable=False)

    admin_username = Column(String(100), nullable=False)
    action_type    = Column(String(100), nullable=False)
    change_before  = Column(Text, nullable=True)
    change_after   = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------
class NetworkTopology(Base):
    __tablename__ = 'network_topology'

    id           = _uuid_col(pk=True)
    device_name  = Column(String(100), nullable=False)
    device_type  = Column(String(50), nullable=False)   # firewall / router / switch / server / endpoint
    zone         = Column(String(50), index=True, nullable=True)
    ip_address   = _inet_col()
    ports_open   = Column(JSON, default=list, nullable=False)
    connected_to = Column(JSON, default=list, nullable=False)
    vlan_id      = Column(Integer, nullable=True)
    subnet       = _cidr_col()
    is_entry_point = Column(Boolean, default=False, nullable=False)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Firewall rules
# ---------------------------------------------------------------------------
class FirewallRule(Base):
    __tablename__ = 'firewall_rules'

    id            = _uuid_col(pk=True)
    device_name   = Column(String(100), index=True, nullable=False)
    rule_name     = Column(String(255), nullable=True)
    rule_position = Column(Integer, nullable=True)
    source_ip     = Column(String(50), nullable=False)
    source_port   = Column(String(20), nullable=True)
    dest_ip       = Column(String(50), nullable=False)
    dest_port     = Column(String(20), nullable=True)
    protocol      = Column(String(10), nullable=False)
    action        = Column(String(20), index=True, nullable=False)
    service_name  = Column(String(100), nullable=True)
    hit_count     = Column(Integer, default=0, nullable=False)
    last_hit      = Column(DateTime, nullable=True)
    is_enabled    = Column(Boolean, default=True, index=True, nullable=False)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Rule risk analysis
# ---------------------------------------------------------------------------
class RuleRiskAnalysis(Base):
    __tablename__ = 'rule_risk_analysis'

    id            = _uuid_col(pk=True)
    rule_id       = _uuid_col(fk='firewall_rules.id')
    risk_score    = Column(Numeric(4, 1), index=True, nullable=False)
    risk_level    = Column(String(20), index=True, nullable=False)
    risk_category = Column(String(50), nullable=True)
    reason        = Column(Text, nullable=True)
    cvss_color    = Column(String(20), nullable=True)
    recommendation = Column(Text, nullable=True)
    calculated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    rule = relationship("FirewallRule")


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------
class AttackPath(Base):
    __tablename__ = 'attack_paths'

    id                       = _uuid_col(pk=True)
    entry_point              = Column(String(100), index=True, nullable=False)
    target                   = Column(String(100), nullable=False)
    path_hops                = Column(JSON, default=list, nullable=False)
    total_risk_score         = Column(Numeric(4, 1), nullable=False)
    risk_level               = Column(String(20), index=True, nullable=False)
    attack_difficulty        = Column(Numeric(4, 1), nullable=True)
    vulnerable_ports_in_path = Column(JSON, default=list, nullable=False)
    weakest_link             = Column(String(255), nullable=True)
    calculated_at            = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Config uploads
# ---------------------------------------------------------------------------
class ConfigUpload(Base):
    __tablename__ = 'config_uploads'

    id                = _uuid_col(pk=True)
    filename          = Column(String(255), nullable=False)
    upload_time       = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    file_size         = Column(BigInteger, nullable=False)
    vendor            = Column(String(50), nullable=True)
    ingestion_status  = Column(String(20), default='pending', nullable=False)
    progress_percent  = Column(Integer, default=0, nullable=False)
    configs_processed = Column(Integer, default=0, nullable=False)
    errors_count      = Column(Integer, default=0, nullable=False)
    warnings_count    = Column(Integer, default=0, nullable=False)
    unsupported_count = Column(Integer, default=0, nullable=False)
    error_messages    = Column(JSON, default=list, nullable=False)
    completed_at      = Column(DateTime, nullable=True)
