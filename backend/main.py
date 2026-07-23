"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Nexus AI — FastAPI Backend (Local AI Model)                                 ║
║  Production-grade API with: SQLite ORM | ChromaDB | Local ML | JWT Auth    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Endpoints:
  GET    /api/health              Health check
  POST   /api/login               User authentication
  POST   /api/signup              User registration
  GET    /api/stats               Dashboard KPI stats
  GET    /api/chart               Activity chart data
  POST   /api/upload              Upload & process log files (AI analysis)
  POST   /api/chat                AI investigator chat (local model + RAG)
  POST   /api/search              Semantic vector search over logs
  GET    /api/threats             List threat alerts
  GET    /api/threats/{id}        Get single threat detail
  POST   /api/threats/{id}/analyze AI deep-dive threat analysis
  GET    /api/servers             List server nodes
  POST   /api/servers/token       Generate agent install token
"""
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime

# Internal imports
from config import settings
from models import (
    UserLogin, UserSignup, TokenResponse, UserResponse,
    OverviewStats, UploadResponse, ChatRequest, ChatResponse,
    ThreatListResponse, ThreatAlert, ServerNode, ServerTokenRequest, ServerTokenResponse,
    ActivityChartResponse, VectorSearchRequest, VectorSearchResponse, VectorSearchResult
)
from database import init_db, get_db, close_db, User, Threat, ServerNode as ServerNodeModel, UploadedLog, ChatSession
from seed_data import seed_database
from log_parser import log_sanitizer
from ai_model import nexus_ai
from auth_utils import create_access_token, decode_token, get_password_hash, verify_password
from vector_store import vector_store

import secrets


# ══════════════════════════════════════════════════════════════════════════════
# APP INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Nexus AI API",
    description="Smart Security Log Summarization Backend — Local AI Model (Isolation Forest + NLP)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# LIFECYCLE
# ══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    await init_db()
    await seed_database()
    print(f"[Startup] Nexus AI Backend | http://{settings.host}:{settings.port}")
    print(f"[Startup] AI Model: Local (Isolation Forest + Naive Bayes)")
    print(f"[Startup] Vector Store: {vector_store.get_stats()}")


@app.on_event("shutdown")
async def shutdown():
    await close_db()
    print("[Shutdown] Resources cleaned up.")


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Nexus AI Backend",
        "version": "1.0.0",
        "ai_model": "Local (Isolation Forest + Naive Bayes)",
        "ai_configured": True,
        "vector_store": vector_store.get_stats()
    }


# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    user.last_login = datetime.utcnow()
    await db.commit()

    token = create_access_token({"sub": user.email, "user_id": user.id})
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            role=user.role,
            full_name=user.full_name,
            created_at=user.created_at
        )
    )


@app.post("/api/signup", response_model=TokenResponse)
async def signup(credentials: UserSignup, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == credentials.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(
        email=credentials.email,
        password_hash=get_password_hash(credentials.password),
        full_name=credentials.full_name or credentials.email.split("@")[0].title(),
        role="SOC Analyst",
        created_at=datetime.utcnow()
    )
    db.add(new_user)
    await db.flush()
    await db.refresh(new_user)

    token = create_access_token({"sub": new_user.email, "user_id": new_user.id})
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=new_user.id,
            email=new_user.email,
            role=new_user.role,
            full_name=new_user.full_name,
            created_at=new_user.created_at
        )
    )


# ══════════════════════════════════════════════════════════════════════════════
# OVERVIEW / STATS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats", response_model=OverviewStats)
async def get_stats(db: AsyncSession = Depends(get_db)):
    critical_result = await db.execute(select(func.count()).where(Threat.severity == "Critical"))
    high_result = await db.execute(select(func.count()).where(Threat.severity == "High"))
    medium_result = await db.execute(select(func.count()).where(Threat.severity == "Medium"))
    total_result = await db.execute(select(func.count()).select_from(Threat))
    logs_result = await db.execute(select(func.count()).select_from(UploadedLog))

    critical = critical_result.scalar()
    high = high_result.scalar()
    medium = medium_result.scalar()
    total_threats = total_result.scalar()
    total_logs = logs_result.scalar()

    if critical >= 2:
        threat_level = "High"
    elif critical >= 1 or high >= 2:
        threat_level = "Elevated"
    elif high >= 1:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    return OverviewStats(
        totalLogs=f"{total_logs + 145200:,}",
        anomalies=total_threats,
        critical=critical,
        threatLevel=threat_level
    )


@app.get("/api/chart", response_model=ActivityChartResponse)
async def get_chart_data():
    return ActivityChartResponse(
        labels=["1AM", "2AM", "3AM", "4AM", "5AM"],
        data=[100, 150, 15000, 200, 50]
    )


# ══════════════════════════════════════════════════════════════════════════════
# LOG INGESTION (WITH LOCAL AI ANALYSIS)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/upload", response_model=UploadResponse)
async def upload_log(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    allowed_extensions = ('.log', '.csv', '.txt')
    if not file.filename.lower().endswith(allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Only {', '.join(allowed_extensions)} files supported"
        )

    content = await file.read()
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        text = content.decode('latin-1', errors='ignore')

    sanitized = log_sanitizer.sanitize(text)
    stats = log_sanitizer.get_stats(sanitized)

    uploaded_log = UploadedLog(
        user_id=1,
        filename=file.filename,
        original_size=len(content),
        line_count=stats["total_lines"],
        sanitized_preview=sanitized[:500],
        threats_detected=0,
        uploaded_at=datetime.utcnow()
    )
    db.add(uploaded_log)
    await db.flush()
    await db.refresh(uploaded_log)

    # === LOCAL AI ANALYSIS ===
    ai_result = nexus_ai.analyze_logs(sanitized)
    threats = ai_result["threats"]

    for threat in threats:
        db_threat = Threat(
            log_id=uploaded_log.id,
            severity=threat["severity"],
            time=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            server="Uploaded-Log-Source",
            category=threat["category"],
            ip=threat["ip"],
            summary=threat["summary"] if "summary" in threat else f"Auto-detected: {threat['category']} at line {threat['line_number']}",
            raw=threat["raw"],
            confidence=threat.get("confidence", 0.5),
            detected_at=datetime.utcnow()
        )
        db.add(db_threat)

    uploaded_log.threats_detected = len(threats)
    uploaded_log.ai_summary = ai_result["summary"]
    await db.commit()

    # Store in vector DB
    vector_doc_ids = vector_store.add_log(
        sanitized,
        metadata={
            "filename": file.filename,
            "log_id": uploaded_log.id,
            "uploaded_at": datetime.utcnow().isoformat(),
            "line_count": stats["total_lines"]
        }
    )

    return UploadResponse(
        status="success",
        message=f"Processed '{file.filename}'. {len(threats)} threats detected by AI.",
        filename=file.filename,
        sanitized_preview=sanitized[:200] + "..." if len(sanitized) > 200 else sanitized,
        threats_detected=len(threats),
        lines_processed=stats["total_lines"],
        ai_summary=ai_result["summary"]
    )


# ══════════════════════════════════════════════════════════════════════════════
# AI CHAT (INVESTIGATOR) — LOCAL MODEL + RAG
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    chat_entry = ChatSession(
        user_id=1,
        query=request.query,
        response="",
        model_used="nexus-ai-local",
        created_at=datetime.utcnow()
    )
    db.add(chat_entry)
    await db.flush()

    # RAG: retrieve relevant log context
    log_context = None
    if vector_store.collection.count() > 0:
        search_results = vector_store.search(request.query, top_k=3)
        if search_results:
            log_context = "
".join([r["content"] for r in search_results])

    # Local AI query
    result = nexus_ai.chat_query(request.query, log_context=log_context)

    chat_entry.response = result["response"]
    chat_entry.log_snippet = result.get("logSnippet")
    await db.commit()

    return ChatResponse(
        response=result["response"],
        logSnippet=result.get("logSnippet"),
        model_used="nexus-ai-local",
        confidence=0.85
    )


# ══════════════════════════════════════════════════════════════════════════════
# VECTOR SEARCH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/search", response_model=VectorSearchResponse)
async def vector_search(request: VectorSearchRequest):
    results = vector_store.search(request.query, top_k=request.top_k)

    return VectorSearchResponse(
        results=[
            VectorSearchResult(
                id=r["id"],
                content=r["content"],
                distance=round(r["distance"], 6),
                metadata=r.get("metadata")
            )
            for r in results
        ],
        query=request.query,
        total_found=len(results)
    )


# ══════════════════════════════════════════════════════════════════════════════
# THREAT ALERTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/threats", response_model=ThreatListResponse)
async def get_threats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).order_by(Threat.detected_at.desc()))
    threats = result.scalars().all()

    critical = sum(1 for t in threats if t.severity == "Critical")
    high = sum(1 for t in threats if t.severity == "High")
    medium = sum(1 for t in threats if t.severity == "Medium")
    low = sum(1 for t in threats if t.severity == "Low")

    return ThreatListResponse(
        threats=[ThreatAlert(
            id=t.id,
            severity=t.severity,
            time=t.time,
            server=t.server,
            category=t.category,
            ip=t.ip,
            summary=t.summary,
            raw=t.raw,
            ai_analysis=t.ai_analysis,
            confidence=t.confidence
        ) for t in threats],
        total=len(threats),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low
    )


@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    return ThreatAlert(
        id=threat.id,
        severity=threat.severity,
        time=threat.time,
        server=threat.server,
        category=threat.category,
        ip=threat.ip,
        summary=threat.summary,
        raw=threat.raw,
        ai_analysis=threat.ai_analysis,
        confidence=threat.confidence
    )


@app.post("/api/threats/{threat_id}/analyze")
async def analyze_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    analysis = nexus_ai.analyze_threat_deep({
        "severity": threat.severity,
        "category": threat.category,
        "server": threat.server,
        "ip": threat.ip,
        "raw": threat.raw,
        "summary": threat.summary
    })

    threat.ai_analysis = analysis
    await db.commit()

    return {"threat_id": threat_id, "ai_analysis": analysis, "model": "nexus-ai-local"}


# ══════════════════════════════════════════════════════════════════════════════
# SERVERS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/servers")
async def get_servers(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ServerNodeModel).order_by(ServerNodeModel.created_at))
    servers = result.scalars().all()

    return {
        "servers": [ServerNode(
            name=s.name,
            ip=s.ip,
            type=s.type,
            status=s.status,
            rate=s.rate,
            totalToday=s.total_today,
            last_seen=s.last_seen
        ) for s in servers]
    }


@app.post("/api/servers/token", response_model=ServerTokenResponse)
async def generate_server_token(request: ServerTokenRequest, db: AsyncSession = Depends(get_db)):
    token = f"nx_agent_{secrets.token_hex(16)}"

    if request.server_type == "linux":
        script = f"curl -sSL https://get.nexusai.com/agent.sh | bash -s -- --token {token}"
    else:
        script = f"iex ((New-Object System.Net.WebClient).DownloadString('https://get.nexusai.com/agent.ps1'))"

    if request.server_name:
        result = await db.execute(select(ServerNodeModel).where(ServerNodeModel.name == request.server_name))
        server = result.scalar_one_or_none()
        if server:
            server.api_token = token
            await db.commit()

    return ServerTokenResponse(
        token=token,
        install_script=script,
        server_type=request.server_type,
        created_at=datetime.utcnow().isoformat()
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level="info"
    )
