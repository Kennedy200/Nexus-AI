"""
Nexus AI — Pydantic Data Models
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════

class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


class UserSignup(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: Optional[str] = "Admin User"


class UserResponse(BaseModel):
    id: int
    email: str
    role: str = "Senior SOC Security Analyst"
    full_name: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ════════════════════════════════════════════════════════════
# OVERVIEW / STATS
# ════════════════════════════════════════════════════════════

class OverviewStats(BaseModel):
    totalLogs: str
    anomalies: int
    critical: int
    threatLevel: str


class ActivityChartResponse(BaseModel):
    labels: List[str]
    data: List[int]


# ════════════════════════════════════════════════════════════
# LOG INGESTION
# ════════════════════════════════════════════════════════════

class UploadResponse(BaseModel):
    status: str
    message: str
    filename: Optional[str] = None
    sanitized_preview: Optional[str] = None
    threats_detected: Optional[int] = None
    lines_processed: Optional[int] = None
    ai_summary: Optional[str] = None


# ════════════════════════════════════════════════════════════
# AI CHAT (INVESTIGATOR)
# ════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    query: str = Field(min_length=1)
    context: Optional[str] = "security_logs"


class ChatResponse(BaseModel):
    response: str
    logSnippet: Optional[str] = None
    model_used: str = "nexus-ai-local"
    confidence: Optional[float] = None


# ════════════════════════════════════════════════════════════
# THREAT ALERTS
# ════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ThreatAlert(BaseModel):
    id: int
    severity: Severity
    time: str
    server: str
    category: str
    ip: str
    summary: str
    raw: str
    ai_analysis: Optional[str] = None
    confidence: Optional[float] = None

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    threats: List[ThreatAlert]
    total: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


# ════════════════════════════════════════════════════════════
# SERVERS
# ════════════════════════════════════════════════════════════

class ServerStatus(str, Enum):
    ONLINE = "online"
    WARNING = "warning"
    OFFLINE = "offline"


class ServerNode(BaseModel):
    name: str
    ip: str
    type: str
    status: ServerStatus
    rate: str
    totalToday: str
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True


class ServerTokenRequest(BaseModel):
    server_type: str = Field(default="linux", pattern="^(linux|windows)$")
    server_name: Optional[str] = None


class ServerTokenResponse(BaseModel):
    token: str
    install_script: str
    server_type: str
    created_at: str


# ════════════════════════════════════════════════════════════
# VECTOR SEARCH
# ════════════════════════════════════════════════════════════

class VectorSearchRequest(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=20)


class VectorSearchResult(BaseModel):
    id: str
    content: str
    distance: float
    metadata: Optional[dict] = None


class VectorSearchResponse(BaseModel):
    results: List[VectorSearchResult]
    query: str
    total_found: int
