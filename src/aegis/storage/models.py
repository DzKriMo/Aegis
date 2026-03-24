from __future__ import annotations

from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey

Base = declarative_base()


class Tenant(Base):
    __tablename__ = "aegis_tenants"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, unique=True)


class ApiKey(Base):
    __tablename__ = "aegis_api_keys"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("aegis_tenants.id"), nullable=False)
    key = Column(String(128), nullable=False, unique=True)
    active = Column(Boolean, default=True)


class SessionRecord(Base):
    __tablename__ = "aegis_sessions"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), nullable=False, unique=True)
    tenant_id = Column(Integer, ForeignKey("aegis_tenants.id"), nullable=True)
    created_at = Column(Integer, nullable=True)
    title = Column(String(200), nullable=True)


class EventRecord(Base):
    __tablename__ = "aegis_events"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), nullable=False)
    stage = Column(String(64), nullable=True)
    payload = Column(Text, nullable=False)


class PolicyRecord(Base):
    __tablename__ = "aegis_policies"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    stage = Column(String(32), nullable=False)
    action = Column(String(32), nullable=False)
    match_json = Column(Text, nullable=False)
    risk = Column(String(32), nullable=True)
    enabled = Column(Boolean, default=True)


class ToolPolicyRecord(Base):
    __tablename__ = "aegis_tool_policies"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False, unique=True)
    allowed_envs = Column(Text, nullable=True)  # JSON array
    allowlist = Column(Text, nullable=True)  # JSON array
    timeout_seconds = Column(Integer, nullable=False, default=5)
    max_bytes = Column(Integer, nullable=True)


class ApprovalRecord(Base):
    __tablename__ = "aegis_approvals"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), nullable=True)
    approval_hash = Column(String(128), nullable=False, index=True)
    scope = Column(String(32), nullable=False, default="exact")
    actor = Column(String(128), nullable=True)
    reason = Column(Text, nullable=True)
    stage = Column(String(32), nullable=True)
    tool_name = Column(String(64), nullable=True)
    tenant_id = Column(String(128), nullable=True)
    environment = Column(String(64), nullable=True)
    reusable = Column(Boolean, default=True)
    active = Column(Boolean, default=True)
    expires_at = Column(Integer, nullable=True)
    metadata_json = Column(Text, nullable=True)
