# 🔒 Firewall Rule Reviewer

A production-grade firewall configuration analysis tool. Upload firewall configs (Palo Alto, Cisco ASA, FortiGate) or traffic log data and get instant risk analysis, attack path simulation, threat detection, and remediation recommendations.

---

## Quick Start

### Windows
Double-click `START.bat`

### Linux / Mac
```bash
./START.sh
```

Then open **http://localhost:8080**

---

## Architecture

```
fortress-lens-main/   ← React + Vite frontend (port 8080)
  src/
    lib/api.ts         ← All API calls to the backend (SINGLE source of truth)
    pages/             ← Dashboard, LiveTraffic, Threats, Analysis, AttackPaths, Remediation
    components/
      upload/          ← UploadModal (config + data file uploads)
      layout/          ← AppLayout + AppSidebar

main.py               ← FastAPI entry point (port 8000)
backend_topology.py   ← All API endpoints
api/upload.py         ← /api/upload-data, /api/validate-upload, /api/download-template
parsers/              ← Palo Alto XML, Cisco ASA, FortiGate config parsers
utils/                ← risk_engine, attack_path_engine, template_generator
database/             ← SQLAlchemy models + async connection
```

---

## Manual Setup

### Backend

```bash
# From the project root
pip install -r requirements.txt
cp .env.example .env        # edit DATABASE_URL if needed
python main.py              # or: uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd fortress-lens-main
npm install
npm run dev                 # Vite dev server on :8080, proxies /api → :8000
```

---

## Uploading Data

The **Upload** button on the Dashboard opens a modal for data ingestion.

### 1. Firewall Config (XML / Conf)
Upload raw firewall configuration files to populate **Analysis**, **Topology**, **Risk**, and **Attack Paths**.

| Vendor | File type | Detection |
|--------|-----------|-----------|
| Palo Alto (PAN-OS) | `.xml` | Extension |
| Cisco ASA | `.conf` | Extension or `asa` in filename |
| FortiGate | Any | `forti` in filename |

**Note:** The backend calculates risk and attack paths strictly from the uploaded rules and topology.

### 2. Traffic / Log Data (CSV / JSON)
**Required for Live Traffic & Threats.**
Upload connection logs in `.csv`, `.json`, or `.xlsx` format to populate **Live Traffic** and **Threats**.
*   This application does **not** generate mock traffic data.
*   If no CSV is uploaded, the traffic and threat views will remain empty.
*   Use the "Download Template" feature in the API or check `test_upload.csv` for the schema.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload-config` | Upload + detect vendor, start background parse |
| `POST` | `/api/parse-config/{id}` | Re-trigger parse for an existing upload |
| `POST` | `/api/upload-data` | Ingest traffic/log CSV/JSON/XLSX |
| `POST` | `/api/validate-upload` | Validate a file before ingestion |
| `GET`  | `/api/download-template?format=csv\|json\|excel` | Download blank template |
| `GET`  | `/api/ingestion-status` | Latest upload status + progress |
| `GET`  | `/api/topology/summary` | Zone/rule/device counts |
| `GET`  | `/api/analytics/summary` | Connection counts, bytes, protocols |
| `POST` | `/api/analyze-rules` | Trigger background risk analysis |
| `GET`  | `/api/risk-analysis/summary` | Risk level counts + avg score |
| `GET`  | `/api/risky-rules` | Rules with score ≥ threshold |
| `GET`  | `/api/vulnerable-ports` | Exposed ports across topology |
| `POST` | `/api/analyze-reachability` | Zone reachability analysis |
| `POST` | `/api/analyze-attack-paths` | Trigger attack path calculation |
| `GET`  | `/api/attack-paths` | Fetch calculated attack paths |
| `GET`  | `/api/attack-paths/summary` | Critical/high path counts |
| `GET`  | `/api/malware-entry-points` | Identified entry point nodes |
| `GET`  | `/api/threats` | Threat log entries |
| `GET`  | `/api/connections` | Connection log entries |
| `GET`  | `/api/remediation` | Prioritised remediation items |
| `GET`  | `/api/rule-stats` | Total/enabled/disabled rule counts |
| `GET`  | `/api/health` | Health check |

Full interactive docs: **http://localhost:8000/docs**

---

## Frontend ↔ Backend Connection

The Vite dev server proxies all `/api/*` requests to `http://localhost:8000` via `vite.config.ts`:

```ts
proxy: {
  "/api": { target: "http://localhost:8000", changeOrigin: true }
}
```

**All API calls live in `src/lib/api.ts`** — one central file. Every page imports from there. The UI connects directly to the backend to display real data. If there is no data, the UI will intuitively prompt users to upload their configuration or logs. No mock data is used in production.

---

## Environment Variables

```env
# .env
DATABASE_URL=sqlite+aiosqlite:///./firewall.db   # default SQLite
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost/firewall  # for Postgres
```

---

## Production Build

```bash
# Build frontend static files
cd fortress-lens-main
npm run build               # outputs to dist/

# Serve frontend via FastAPI static files (optional)
# Add to main.py: app.mount("/", StaticFiles(directory="fortress-lens-main/dist", html=True))

# Or deploy separately:
# Frontend → Vercel / Nginx
# Backend  → Gunicorn + Uvicorn workers behind Nginx
```

---

## Docker Deployment (GPU / Lightning.ai)

This repo includes containerized deployment for NVIDIA GPU environments using:

- CUDA runtime base image: `nvidia/cuda:12.1.0-runtime-ubuntu22.04`
- Backend port: `8000`
- Frontend port: `8501`
- Model mount path in container: `/app/model`

### Prerequisites

```bash
docker --version
docker compose version
```

For GPU support, ensure Docker can access NVIDIA devices on the host.

Create local runtime assets in the project root:

```bash
mkdir -p model
# Place your model files inside ./model
# Ensure firewall.db exists (or let the app create it)
```

### Option A: Split Services (Recommended for local testing)

Runs backend and frontend as separate containers.

```bash
docker compose build backend frontend
docker compose up -d backend frontend
```

Open:

- Frontend: `http://localhost:8501`
- Backend API docs: `http://localhost:8000/docs`

Stop:

```bash
docker compose down
```

### Option B: Single Black-Box Container

Runs backend + frontend in one container using `start.sh`.

```bash
docker compose --profile blackbox build blackbox
docker compose --profile blackbox up -d blackbox
```

Open:

- App: `http://localhost:8501`
- API docs: `http://localhost:8000/docs`

Stop:

```bash
docker compose --profile blackbox down
```

### Logs and Health Checks

```bash
docker compose logs -f backend frontend
docker compose --profile blackbox logs -f blackbox
curl http://localhost:8000/api/health
```

### Docker Files Included

- `Dockerfile` (multi-stage with `backend-runtime`, `frontend-runtime`, `all-in-one-runtime` targets)
- `docker-compose.yml` (GPU-enabled services + optional blackbox profile)
- `docker/nginx.frontend.conf` (frontend container proxy to backend service)
- `docker/nginx.local.conf` (all-in-one proxy to localhost backend)
- `start.sh` (runs backend and nginx in a single container)
- `.dockerignore` (build context cleanup)
