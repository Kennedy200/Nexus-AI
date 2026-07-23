# Nexus AI — Backend (Local AI Model)

Production-grade FastAPI backend with **embedded ML model** for security log analysis. No cloud API required — everything runs locally on CPU.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI (Port 8001)                     │
├──────────────┬──────────────┬──────────────┬──────────────────┤
│   Auth       │   SQLite     │  ChromaDB    │   Local AI       │
│   (JWT)      │   (ORM)      │  (Vectors)   │   (Isolation     │
│              │              │              │    Forest + NB)  │
└──────────────┴──────────────┴──────────────┴──────────────────┘
```

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **API Framework** | FastAPI + Uvicorn | Async HTTP API |
| **Database** | SQLite + aiosqlite + SQLAlchemy ORM | Persistent relational storage |
| **Vector DB** | ChromaDB (persistent) | Semantic log search, RAG retrieval |
| **Embeddings** | sentence-transformers `all-MiniLM-L6-v2` | CPU-optimized, ~80MB |
| **AI Model** | Isolation Forest + Naive Bayes + Rule Engine | Local threat detection & analysis |
| **Auth** | JWT (python-jose) + bcrypt | Secure token-based auth |

## AI Model Architecture

### 1. Log Classification (Naive Bayes + TF-IDF)
- **Input:** Raw log line
- **Output:** Attack category (SSH Brute Force, SQL Injection, XSS, Port Scan, etc.)
- **Training:** Synthetic security logs covering 10 attack types + normal traffic
- **Features:** TF-IDF with 1-3 gram range, 1000 max features

### 2. Anomaly Detection (Isolation Forest)
- **Input:** TF-IDF vector of log line
- **Output:** Anomaly score (0-1) + binary anomaly flag
- **Contamination:** 30% (security logs are noisy)
- **Estimators:** 100 trees

### 3. Rule-Based Pattern Matching
- **10 attack signatures** with regex patterns
- **Severity mapping:** Critical/High/Medium/Low
- **Confidence scoring:** Based on pattern match count

### 4. NLP Summarization (Template-Based)
- **Executive briefings** from detected threats
- **MITRE ATT&CK mapping** for known attack types
- **Actionable recommendations** per severity level

### 5. RAG Pipeline (Vector Search + Local AI)
- **Embed** query using sentence-transformers
- **Search** ChromaDB for top-k similar log chunks
- **Inject** retrieved context into AI response generation
- **Return** grounded, factual answers with cited evidence

## Quick Start

### 1. Install Dependencies
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env if needed (defaults work out of the box)
```

### 3. Run the Server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

Or:
```bash
python main.py
```

### 4. Verify
```bash
curl http://localhost:8001/api/health
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check + AI model status |
| `POST` | `/api/login` | Authenticate user |
| `POST` | `/api/signup` | Register new user |
| `GET` | `/api/stats` | Dashboard KPI stats (live DB counts) |
| `GET` | `/api/chart` | Activity chart data |
| `POST` | `/api/upload` | Upload log → AI analysis → detect threats |
| `POST` | `/api/chat` | AI investigator chat (RAG + local model) |
| `POST` | `/api/search` | Semantic vector search over logs |
| `GET` | `/api/threats` | List all threat alerts |
| `GET` | `/api/threats/{id}` | Single threat detail |
| `POST` | `/api/threats/{id}/analyze` | Deep AI threat analysis |
| `GET` | `/api/servers` | List monitored servers |
| `POST` | `/api/servers/token` | Generate agent install token |

## Connecting Frontend

Update `frontend/dashboard.js`:
```javascript
const NexusAPI = {
    BASE_URL: "http://localhost:8001/api",
    // ... rest stays the same
};
```

Run frontend:
```bash
cd ../frontend
python3 -m http.server 8000
```

Open: `http://localhost:8000/dashboard.html`

## Database Schema

### Users
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| email | STRING(255) | Unique, indexed |
| password_hash | STRING(255) | bcrypt hashed |
| full_name | STRING(255) | Display name |
| role | STRING(100) | SOC role |
| created_at | DATETIME | Registration time |
| last_login | DATETIME | Last auth time |

### Threats
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| log_id | INTEGER FK | Reference to uploaded log |
| severity | STRING(20) | Critical/High/Medium/Low |
| time | STRING(50) | Event timestamp |
| server | STRING(200) | Source server |
| category | STRING(200) | Attack type |
| ip | STRING(50) | Source IP |
| summary | TEXT | Human-readable summary |
| raw | TEXT | Raw log line |
| ai_analysis | TEXT | AI-generated deep analysis |
| confidence | FLOAT | Model confidence (0-1) |
| detected_at | DATETIME | Detection time |

### UploadedLogs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Uploader |
| filename | STRING(500) | Original filename |
| original_size | INTEGER | File size in bytes |
| line_count | INTEGER | Number of lines |
| sanitized_preview | TEXT | Redacted preview |
| threats_detected | INTEGER | AI-detected threats |
| ai_summary | TEXT | AI analysis result |
| uploaded_at | DATETIME | Upload time |

### Servers
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| name | STRING(200) | Unique server name |
| ip | STRING(50) | Server IP |
| type | STRING(200) | OS/Platform |
| status | STRING(20) | online/warning/offline |
| rate | STRING(50) | Logs/sec |
| total_today | STRING(50) | Daily log count |
| api_token | STRING(255) | Agent auth token |
| last_seen | DATETIME | Heartbeat time |

### ChatSessions
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Asker |
| query | TEXT | User question |
| response | TEXT | AI response |
| model_used | STRING(50) | "nexus-ai-local" |
| log_snippet | TEXT | Referenced log |
| confidence | FLOAT | Response confidence |
| created_at | DATETIME | Chat time |

## RAG Pipeline

When you chat with the AI Investigator:

1. **Embed** your query with `all-MiniLM-L6-v2`
2. **Search** ChromaDB for top-3 similar log chunks (cosine similarity)
3. **Inject** retrieved chunks as context to the local AI model
4. **Generate** response using intent classification + template filling
5. **Return** grounded answer with cited log evidence

## Detected Attack Categories

| Category | Severity | Patterns |
|----------|----------|----------|
| SSH Brute Force | High | Failed passwords, invalid users |
| SQL Injection | Critical | UNION SELECT, OR 1=1, comment injection |
| XSS Attack | High | `<script>`, `javascript:`, event handlers |
| Port Scanning | Medium | Sequential SYN, nmap signatures |
| Privilege Escalation | High | sudo failures, su auth failures |
| Malware Download | Critical | wget/curl of .sh/.bin files |
| Ransomware Indicator | Critical | Encryption, bitcoin demands |
| Data Exfiltration | Critical | mysqldump, scp of sensitive files |
| DDoS Attack | Critical | Connection floods, SYN floods |
| Directory Traversal | High | `../`, `%2e%2e`, passwd access |
| Normal | Low | Standard operational logs |

## File Structure

```
backend/
├── main.py              # FastAPI app — all routes
├── config.py            # Environment settings
├── models.py            # Pydantic request/response schemas
├── database.py          # SQLAlchemy ORM + async SQLite
├── vector_store.py      # ChromaDB semantic search
├── ai_model.py          # Local ML model (Isolation Forest + NB)
├── log_parser.py        # PII sanitizer
├── auth_utils.py        # JWT + bcrypt utilities
├── seed_data.py         # Demo data population
├── requirements.txt     # Python dependencies
├── .env.example         # Config template
└── README.md            # This file
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key` | JWT signing key |
| `CORS_ORIGINS` | `*` | Allowed frontend origins |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8001` | Server port |
| `DATABASE_URL` | `sqlite+aiosqlite:///./nexus_ai.db` | SQLite path |
| `CHROMA_DB_PATH` | `./chroma_db` | Vector store path |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Embedding model |
| `ANOMALY_THRESHOLD` | `0.75` | Anomaly detection threshold |

## Demo Credentials

| Email | Password | Role |
|-------|----------|------|
| `admin@nexusai.com` | `admin123` | Senior SOC Security Analyst |

## Production Notes

- **SQLite** works for single-user demo. For production, migrate to PostgreSQL.
- **ChromaDB** persists to `./chroma_db/`. Back it up.
- **ML models** auto-train on first startup and save to `./ml_models/`.
- **JWT secret** must be cryptographically random in production.
- **CORS** should restrict origins in production (not `*`).
- **Rate limiting** recommended for production (e.g., `slowapi`).
- **HTTPS** required in production. Use nginx/Caddy reverse proxy.
