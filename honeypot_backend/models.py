"""
Pydantic schemas for API responses and WebSocket events.
"""

from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel
from datetime import datetime


# ── REST response models ───────────────────────────────────────────────────────

class ActivityLogOut(BaseModel):
    id: int
    timestamp: str
    event_type: str
    service: str
    source_ip: str
    source_port: Optional[int]
    details: str
    success: bool
    raw_data: Optional[str]


class ThreatOut(BaseModel):
    id: int
    timestamp: str
    type: str
    source_ip: str
    target_service: str
    severity: str
    description: str
    details: Optional[str]


class ServiceStatOut(BaseModel):
    service_id: str
    total_connections: int
    failed_auths: int
    commands_captured: int
    last_activity: Optional[str]
    status: str = "active"   # filled in dynamically by service manager
    port: int = 0            # filled in dynamically


class SummaryStats(BaseModel):
    total_connections: int
    blocked_attacks: int
    active_threats: int
    services_running: int


class SystemStats(BaseModel):
    cpu_percent: float
    memory_percent: float
    network_bytes_sent: int
    network_bytes_recv: int


class FullStats(BaseModel):
    honeypot: SummaryStats
    system: SystemStats


# ── WebSocket event payloads ───────────────────────────────────────────────────

class WsActivityEvent(BaseModel):
    event: Literal["activity_log"] = "activity_log"
    data: ActivityLogOut


class WsThreatEvent(BaseModel):
    event: Literal["threat"] = "threat"
    data: ThreatOut


class WsServiceUpdate(BaseModel):
    event: Literal["service_update"] = "service_update"
    data: ServiceStatOut


class WsStatsUpdate(BaseModel):
    event: Literal["stats"] = "stats"
    data: FullStats


class WsHoneypotToggle(BaseModel):
    event: Literal["honeypot_toggle"] = "honeypot_toggle"
    active: bool
