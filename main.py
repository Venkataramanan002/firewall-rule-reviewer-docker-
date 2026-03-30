import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import os
import uvicorn
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from backend_topology import app as topology_app
from database.connection import init_db
from api.enterprise import router as enterprise_router
from api.ip_analysis import router as ip_analysis_router

load_dotenv()

app = topology_app

# ── Register API routers ──────────────────────────────────────────────────────
app.include_router(enterprise_router)
app.include_router(ip_analysis_router)

# ── CORS ──────────────────────────────────────────────────────────────────────
_raw_origins = os.getenv("CORS_ORIGINS", "").strip()
if _raw_origins == "*":
    _allowed_origins = ["*"]
elif _raw_origins:
    _allowed_origins = [o.strip() for o in _raw_origins.split(",")]
else:
    _allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:8080",
        "http://localhost:8081",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    await init_db()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)