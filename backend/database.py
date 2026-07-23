"""
Nexus AI — Database Layer
SQLAlchemy async ORM with SQLite.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from datetime import datetime
from typing import AsyncGenerator
from config import settings


engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), default="Admin User")
    role = Column(String(100), default="SOC Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    uploaded_logs = relationship("UploadedLog", back_populates="user", lazy="selectin")
    chat_sessions = relationship("ChatSession", back_populates="user", lazy="selectin")


class UploadedLog(Base):
    __tablename__ = "uploaded_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(500), nullable=False)
    original_size = Column(Integer, default=0)
    line_count = Column(Integer, default=0)
    sanitized_preview = Column(Text)
    threats_detected = Column(Integer, default=0)
    ai_summary = Column(Text, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="uploaded_logs")
    threats = relationship("Threat", back_populates="log", lazy="selectin")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("uploaded_logs.id"), nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    time = Column(String(50), nullable=False)
    server = Column(String(200), nullable=False)
    category = Column(String(200), nullable=False, index=True)
    ip = Column(String(50), nullable=False)
    summary = Column(Text, nullable=False)
    raw = Column(Text, nullable=False)
    ai_analysis = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

    log = relationship("UploadedLog", back_populates="threats")


class ServerNode(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False)
    ip = Column(String(50), nullable=False)
    type = Column(String(200), nullable=False)
    status = Column(String(20), default="online")
    rate = Column(String(50), default="0 logs/sec")
    total_today = Column(String(50), default="0")
    api_token = Column(String(255), nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    query = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    model_used = Column(String(50), default="nexus-ai-local")
    log_snippet = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="chat_sessions")


class VectorLogEntry(Base):
    __tablename__ = "vector_log_entries"

    id = Column(Integer, primary_key=True, index=True)
    chroma_doc_id = Column(String(100), unique=True, nullable=False, index=True)
    log_id = Column(Integer, ForeignKey("uploaded_logs.id"), nullable=True)
    content_preview = Column(Text, nullable=False)
    embedding_model = Column(String(100), default="all-MiniLM-L6-v2")
    created_at = Column(DateTime, default=datetime.utcnow)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db():
    await engine.dispose()
