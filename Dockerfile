# syntax=docker/dockerfile:1.6

# ---------- Frontend build stage ----------
FROM node:20-bookworm-slim AS frontend-builder
WORKDIR /build/frontend

COPY fortress-lens-main/package*.json ./
RUN npm ci

COPY fortress-lens-main/ ./
RUN npm run build


# ---------- Python dependency build stage ----------
FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04 AS python-builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    python3.10-venv \
    python3-pip \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/backend
COPY requirements.txt ./

RUN python3.10 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ---------- Backend runtime target ----------
FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04 AS backend-runtime
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV MODEL_DIR=/app/model

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv

# Copy only runtime backend files (no frontend source)
COPY main.py alembic.ini ./
COPY api ./api
COPY database ./database
COPY collectors ./collectors
COPY config ./config
COPY migrations ./migrations
COPY alembic ./alembic
COPY parsers ./parsers
COPY services ./services
COPY utils ./utils
COPY backend_topology.py ./backend_topology.py

RUN mkdir -p /app/model /app/data

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


# ---------- Frontend runtime target ----------
FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04 AS frontend-runtime
ENV DEBIAN_FRONTEND=noninteractive
ENV MODEL_DIR=/app/model

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=frontend-builder /build/frontend/dist /srv/frontend
COPY docker/nginx.frontend.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /app/model

EXPOSE 8501
CMD ["nginx", "-g", "daemon off;"]


# ---------- All-in-one runtime target (Black Box single container) ----------
FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04 AS all-in-one-runtime
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV MODEL_DIR=/app/model

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    nginx \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv

COPY main.py alembic.ini ./
COPY api ./api
COPY database ./database
COPY collectors ./collectors
COPY config ./config
COPY migrations ./migrations
COPY alembic ./alembic
COPY parsers ./parsers
COPY services ./services
COPY utils ./utils
COPY backend_topology.py ./backend_topology.py

COPY --from=frontend-builder /build/frontend/dist /srv/frontend
COPY docker/nginx.local.conf /etc/nginx/conf.d/default.conf
COPY start.sh /app/start.sh

RUN mkdir -p /app/model /app/data \
    && chmod +x /app/start.sh

EXPOSE 8000 8501
ENTRYPOINT ["/app/start.sh"]
