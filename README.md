Here is the clean, complete README.md file again, formatted and ready for you to
copy and paste directly into your root nexus-ai/ folder:

# Nexus AI - Smart Security Log Summarization Tool

## 1. Short Description
Nexus AI is a modern, component-based web application designed to eliminate "alert fatigue" for Security Operations Center (SOC) analysts. It ingests voluminous raw security logs (firewalls, server auth, intrusion detection systems), sanitizes them, and leverages Large Language Models (LLMs) to generate human-readable threat summaries, group anomalies, and provide an interactive AI chat interface for incident investigation.

---

## 2. Why Nexus AI?
Traditional SIEM tools generate thousands of noisy alerts daily, making it easy for security analysts to miss critical intrusions. Nexus AI acts as a Level-1 SOC Analyst by automating log interpretation, contextualizing attacks, and presenting actionable security insights in real time via a sleek, minimalistic dashboard.

---

## 3. Tech Stack
### **Frontend (Completed)**
*   **Core:** Vanilla HTML5, CSS3, Modern JavaScript (ES6+ Modules)
*   **Architecture:** Component-based UI with dynamic client-side injection via JavaScript `fetch()`.
*   **Styling:** Custom CSS with CSS variables, Flexbox/Grid, and Light Mode aesthetic.
*   **Libraries:** Chart.js (via CDN for sleek activity volume curves), FontAwesome (Icons).

### **Backend (Your Partner's Domain - Ready for Setup)**
*   **Framework:** Python + FastAPI (Asynchronous, high-performance API).
*   **AI Engine:** LangChain / LlamaIndex + OpenAI (GPT-4o) or Local LLMs (Llama-3 via Ollama).
*   **Database:** PostgreSQL (User data, audit logs) + Vector DB (Pinecone, ChromaDB, or pgvector for log embeddings).

---

## 4. Architecture Diagram
```mermaid
graph TD
    subgraph Client_Layer [Frontend: HTML/CSS/JS (Port 8000)]
        UI[Dashboard Views / Components]
        API_Client[NexusAPI Object (fetch wrapper)]
        UI <--> API_Client
    end

    API_Client -- HTTP / REST API (CORS Enabled) --> Gateway

    subgraph Backend_Layer [Backend: Python FastAPI (Port 8000)]
        Gateway[FastAPI Endpoints]
        Sanitizer[Log Parser & PII Redactor]
        LangChain[AI Orchestrator / Prompt Engine]
        Gateway --> Sanitizer
        Sanitizer --> LangChain
    end

    subgraph Data_Layer [Data & AI Layer]
        Postgres[(PostgreSQL DB)]
        VectorDB[(Vector Embeddings DB)]
        LLM((OpenAI / Local LLM))
    end

    LangChain <--> Postgres
    LangChain <--> VectorDB
    LangChain <--> LLM

5. Flowchart (System Workflow)

[User / Server Agent] 
       │
       ├─> Uploads Log File OR Streams via API Key
       │
[Frontend: Log Ingestion View]
       │
       ├─> Sends Multi-part Form Data -> POST /api/upload
       │
[Backend: FastAPI]
       │
       ├─> Sanitizes logs (strips passwords/PII)
       ├─> Chunks data & generates embeddings -> Saves to [Vector DB]
       ├─> Sends prompt + chunks to [LLM]
       ├─> Receives AI Threat Summary -> Saves to [PostgreSQL]
       │
[Frontend: Overview & Threat Alerts Dashboard]
       │
       ├─> Fetches JSON data -> GET /api/stats & GET /api/threats
       ├─> Renders KPI cards, sleek activity charts, and alert tables

6. Frontend Directory Structure & Routing Guide

(Backend Developer Guide: Use this map to know where the UI calls your
endpoints).

nexus-ai/
├── backend/                        <-- YOUR PARTNER'S DOMAIN (FastAPI setup goes here)
└── frontend/                       <-- COMPLETED FRONTEND
    ├── index.html                  # Landing Page Shell
    ├── global.css                  # Global variables & light-mode resets
    ├── app.js                      # Landing page component loader
    ├── login.html                  # Split-screen Login Page
    ├── signup.html                 # Split-screen Sign Up Page
    ├── auth.css                    # Shared auth styling
    ├── auth.js                     # Auth form handler & router to dashboard
    ├── dashboard.html              # Main Dashboard Shell (Sidebar + Header + Content)
    ├── dashboard.css               # Dashboard layout & Light Mode variables
    ├── dashboard.js                # Central Router (navigateTo) & NexusAPI connector
    └── dashboard-components/       # Modular dashboard views
        ├── sidebar/                # Navigation (Overview, Logs, Chat, Alerts, Servers, Settings, Logout)
        ├── header/                 # Top bar with Server Environment Dropdown
        ├── overview/               # Home View: KPIs, AI Threat Briefing, Chart.js curve
        ├── log-ingestion/          # File upload dropzone with 3-state sleek file preview card
        ├── ai-investigator/        # Full-screen ChatGPT-style log query interface
        ├── threat-alerts/          # Filterable threat table, severity badges & raw log modal
        ├── servers/                # Infrastructure nodes grid & bash agent install script modal
        └── settings/               # Tabbed settings panel (Profile, AI Rules, API Keys, Notifications)

Routing Rules for the Backend Developer:

  - Authentication Flow: signup.html or login.html submits credentials via
    auth.js \rightarrow Routes user to dashboard.html.
  - Dashboard Navigation: Clicking sidebar links triggers
    window.navigateTo(viewName) inside dashboard.js. This dynamically fetches
    the corresponding HTML, CSS, and JS from dashboard-components/[viewName]/.
  - Active Views & Corresponding Backend Endpoints Needed:
    1.  overview \rightarrow Needs GET /api/stats (KPIs, threat levels) &
        Activity Chart data.
    2.  log-ingestion \rightarrow Needs POST /api/upload (multipart file
        handler).
    3.  ai-investigator \rightarrow Needs POST /api/chat (LLM query prompt
        handler).
    4.  threat-alerts \rightarrow Needs GET /api/threats (list of anomalous
        events).
    5.  servers \rightarrow Needs GET /api/servers & POST /api/servers/token.

7. Key Features of the Application

1.  Landing Page: Responsive marketing page featuring features, an explanation
    of how it works, and routing to auth screens.
2.  Split-Screen Auth: Modern login/signup flows with persuasive security copy
    on the left and clean forms on the right.
3.  Security Overview Dashboard: Real-time metrics (Total logs, anomalies,
    critical threats) paired with a sleek gradient curve chart and AI threat
    briefing.
4.  Interactive Log Ingestion: Drag-and-drop file upload zone that morphs into a
    detailed file preview card upon successful ingestion.
5.  AI Investigator Chat: Natural language investigation tool to query logs with
    pre-built prompt chips and log code block formatting.
6.  Threat Alerts Manager: Sortable and searchable table with severity pills
    (Critical, High, Medium) and raw-evidence popups.
7.  Server Infrastructure Monitor: Status cards monitoring live log rates
    (logs/sec) across multiple server nodes with one-line agent installation
    scripts.
8.  Comprehensive Settings: Tabbed UI for managing profiles, AI sensitivity
    thresholds, and API keys.

8. Steps to Run the Project Locally (Setup Guide)

Prerequisites

  - Node.js (optional, but a simple server is required to resolve component
    fetch() requests).
  - Python 3.x installed on your computer.

Step 1: Clone / Open the Repository

Open your terminal in the root nexus-ai/ folder.

Step 2: Run the Frontend Server

Because the frontend dynamically fetches HTML components (fetch()), you must
serve it via a local HTTP server (opening index.html directly from your file
system will trigger CORS/fetch blocks).

Navigate to the frontend folder and start Python's built-in server:

cd frontend
python -m http.server 8000

Open your browser and navigate to:

  - Landing Page: http://localhost:8000/index.html
  - Login Page: http://localhost:8000/login.html
  - Dashboard: http://localhost:8000/dashboard.html

Step 3: Setup the Backend (For the Backend Developer)

1.  Navigate to the backend folder from the root:
    cd backend
2.  Create and activate a Python virtual environment:
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
3.  Install required FastAPI dependencies (suggested):
    pip install fastapi uvicorn pydantic langchain openai psycopg2-binary
4.  Configure CORS in your FastAPI main.py so it accepts requests from the
    frontend (http://localhost:8000):
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], # Update to specific frontend origin in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
5.  Run the FastAPI development server:
    uvicorn main:app --reload --port 8000
    (Note: If running both frontend and backend on port 8000, map FastAPI to
    port 8001 and update BASE_URL inside frontend/dashboard.js).

# Nexus-AI
