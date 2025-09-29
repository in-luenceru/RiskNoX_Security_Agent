"""
RiskNoX Security Manager - Main FastAPI Application
"""

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response, FileResponse
import structlog
import os

from .api import health, enroll, agents, commands, ui
try:
    from .api import schedules, patches, events
except ImportError:
    schedules = patches = events = None
from .db.database import engine, init_db
from .settings import get_settings
from .ws import ws_router
try:
    from .socketio_server import sio, socketio_app
except ImportError:
    sio = socketio_app = None

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter(
    'manager_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'manager_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

AGENT_CONNECTIONS = Counter(
    'manager_agent_connections_total',
    'Total agent connections',
    ['status']
)

COMMANDS_SENT = Counter(
    'manager_commands_sent_total',
    'Total commands sent to agents',
    ['command_type', 'status']
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting RiskNoX Security Manager")
    
    # Initialize database (skip for now to get server running)
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning("Database initialization failed, continuing without DB", error=str(e))
    
    yield
    
    logger.info("Shutting down RiskNoX Security Manager")


# Create FastAPI application
settings = get_settings()

app = FastAPI(
    title="RiskNoX Security Manager",
    description="Centralized command and control server for RiskNoX Security Agents",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# CORS middleware (restrictive in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Admin UI in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Prometheus metrics middleware"""
    start_time = time.time()
    
    response = await call_next(request)
    
    # Record metrics
    duration = time.time() - start_time
    endpoint = request.url.path
    method = request.method
    status_code = response.status_code
    
    REQUEST_COUNT.labels(
        method=method,
        endpoint=endpoint,
        status_code=status_code
    ).inc()
    
    REQUEST_DURATION.labels(
        method=method,
        endpoint=endpoint
    ).observe(duration)
    
    return response


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Request logging middleware"""
    start_time = time.time()
    
    # Log request
    logger.info(
        "Request started",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    
    response = await call_next(request)
    
    # Log response
    duration = time.time() - start_time
    logger.info(
        "Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration * 1000, 2),
    )
    
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with logging"""
    logger.error(
        "Unhandled exception",
        method=request.method,
        path=request.url.path,
        error=str(exc),
        exc_info=True,
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred" if not settings.DEBUG else str(exc),
            "request_id": id(request),
        }
    )


# Prometheus metrics endpoint
@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# Include API routers
app.include_router(health.router, prefix="/api/v1")
app.include_router(enroll.router, prefix="/api/v1")  
app.include_router(agents.router, prefix="/api/v1")
app.include_router(commands.router, prefix="/api/v1")
app.include_router(ui.router, prefix="/api/v1")

# Include WebSocket router
app.include_router(ws_router)

# Mount Socket.IO server for UI communication
if sio and socketio_app:
    app.mount("/socket.io/", socketio_app)
    logger.info("Socket.IO server mounted at /socket.io/")
else:
    logger.warning("Socket.IO not available, UI real-time features will be limited")

if schedules:
    app.include_router(schedules.router, prefix="/api/v1")
if patches:
    app.include_router(patches.router, prefix="/api/v1")
if events:
    app.include_router(events.router, prefix="/api/v1")

# Serve static files (Admin UI)
static_dir = os.path.join(os.path.dirname(__file__), "..", "..", "static", "admin")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    @app.get("/admin/{path:path}")
    async def serve_admin_ui(path: str = ""):
        """Serve the Admin UI"""
        if not path or path == "index.html":
            return FileResponse(os.path.join(static_dir, "index.html"))
        
        file_path = os.path.join(static_dir, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        
        # For client-side routing, return index.html
        return FileResponse(os.path.join(static_dir, "index.html"))
    
    @app.get("/admin")
    async def redirect_to_admin():
        """Redirect /admin to /admin/"""
        return FileResponse(os.path.join(static_dir, "index.html"))


# Root-level health endpoint for convenience
@app.get("/health")
async def root_health():
    """Root health endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "RiskNoX Security Manager"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "RiskNoX Security Manager",
        "version": "0.1.0",
        "status": "operational",
        "docs": "/docs" if settings.DEBUG else "Contact admin for API documentation"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )