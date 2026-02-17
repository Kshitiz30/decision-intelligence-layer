#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# DIL FastAPI Server - Vercel Serverless Entry Point
# Production-Ready REST API for Deterministic Integrity Layer
#
# Endpoints:
#   POST /audit - Process transaction audit
#   GET /ledger - Retrieve full audit ledger
#   GET /health - Service health check
#   GET / - Serve frontend dashboard
# ═══════════════════════════════════════════════════════════════════════════════

import logging
import os
from typing import Dict, Any, List

# --- DIAGNOSTIC STARTUP LOGGING ---
with open('startup.log', 'a') as f:
    import datetime
    f.write(f"\n[{datetime.datetime.now()}] DIL Vercel Serverless Starting Up...\n")
# ---------------------------------

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import uvicorn

# Import the DIL engine from parent directory
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dil_engine import get_dil_engine, AuditRequest, Decision

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("DIL_API")

# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APP INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DIL - Deterministic Integrity Layer",
    description="Enterprise-grade audit & governance engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware (allow local frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# REQUEST/RESPONSE MODELS
# ─────────────────────────────────────────────────────────────────────────────

class AuditRequestModel(BaseModel):
    """API request model for audit endpoint"""
    user_id: str = Field(..., description="User identifier", min_length=1, max_length=255)
    amount: float = Field(..., description="Transaction amount in USD", ge=0, le=10_000_000)
    ai_risk_score: float = Field(..., description="AI-computed risk score (0.0-1.0)", ge=0.0, le=1.0)

    class Config:
        schema_extra = {
            "example": {
                "user_id": "user-12345",
                "amount": 50000.0,
                "ai_risk_score": 0.65
            }
        }

    @validator("ai_risk_score")
    def validate_risk_score(cls, v):
        """Ensure risk score is between 0 and 1"""
        if not (0.0 <= v <= 1.0):
            raise ValueError("ai_risk_score must be between 0.0 and 1.0")
        return v


class AuditResponseModel(BaseModel):
    """API response model for audit endpoint"""
    request_id: str = Field(..., description="Unique request identifier")
    decision: str = Field(..., description="Audit decision (APPROVED/FLAGGED/BLOCKED)")
    reason: str = Field(..., description="Decision reason")
    amount: float = Field(..., description="Transaction amount")
    ai_risk_score: float = Field(..., description="AI risk score")
    sha256_hash: str = Field(..., description="SHA-256 hash of record")
    previous_hash: str | None = Field(None, description="Previous record hash (SHA-256 chain)")
    governance_hash: str = Field(..., description="HMAC-SHA256 governance hash")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    chain_depth: int = Field(..., description="Current ledger depth")

    class Config:
        schema_extra = {
            "example": {
                "request_id": "REQ-ABC12345",
                "decision": "APPROVED",
                "reason": "APPROVED: All guardrails passed (Amount: $50,000.00, Risk: 0.65)",
                "amount": 50000.0,
                "ai_risk_score": 0.65,
                "sha256_hash": "a1b2c3d4e5f6...",
                "previous_hash": "z9y8x7w6v5u4...",
                "governance_hash": "x1y2z3a4b5c6...",
                "timestamp": "2026-02-01T12:34:56.789000",
                "chain_depth": 42
            }
        }


class HealthResponseModel(BaseModel):
    """Health check response"""
    status: str = "healthy"
    service: str = "DIL API"
    ledger_size: int
    chain_integrity: bool


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/audit", response_model=AuditResponseModel, tags=["Audit"])
async def audit_transaction(request: AuditRequestModel) -> Dict[str, Any]:
    """
    Process a transaction audit through the DIL Engine.
    
    Returns a governance report with:
    - Decision (APPROVED/FLAGGED/BLOCKED)
    - SHA-256 hash (part of immutable chain)
    - Governance hash (HMAC-SHA256 for authenticity)
    - Complete audit trail
    
    Guardrail Rules:
    - BLOCKED if amount > $1,000,000
    - BLOCKED if risk_score < 0.5
    - FLAGGED if amount > $100,000 (requires review)
    - FLAGGED if risk_score 0.5-0.7 (elevated risk)
    """
    try:
        logger.info(f"Audit request received: user={request.user_id}, amount=${request.amount:,.2f}, risk={request.ai_risk_score}")

        # Create audit request for engine
        audit_req = AuditRequest(
            user_id=request.user_id,
            amount=request.amount,
            ai_risk_score=request.ai_risk_score
        )

        # Process through DIL Engine
        engine = get_dil_engine()
        decision, reason, record = engine.process_audit(audit_req)

        logger.info(f"Audit complete: decision={decision.value}, request_id={record.request_id}")

        # Format response
        return {
            "request_id": record.request_id,
            "decision": record.decision,
            "reason": record.reason,
            "amount": record.amount,
            "ai_risk_score": record.ai_risk_score,
            "sha256_hash": record.sha256_hash,
            "previous_hash": record.previous_hash,
            "governance_hash": record.governance_hash,
            "timestamp": record.timestamp,
            "chain_depth": engine.get_ledger_size()
        }

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return JSONResponse(status_code=400, content={"error": True, "detail": f"Validation error: {str(e)}"})
    except Exception as e:
        logger.exception(f"Unexpected error during audit: {str(e)}")
        return JSONResponse(status_code=500, content={"error": True, "detail": "Internal server error during audit processing", "exception": str(e)})


@app.get("/ledger", tags=["Ledger"])
async def get_ledger(limit: int = None) -> Dict[str, Any]:
    """
    Retrieve the complete audit ledger.
    
    Query Parameters:
    - limit: Maximum number of recent records to return (optional)
    
    Returns:
    - records: Array of audit records
    - total_count: Total number of records in ledger
    - chain_integrity: SHA-256 chain integrity status
    """
    try:
        engine = get_dil_engine()
        all_records = engine.get_ledger()

        # Apply limit if specified
        if limit and limit > 0:
            records = all_records[-limit:]
        else:
            records = all_records

        logger.info(f"Ledger retrieved: {len(records)} records (total: {len(all_records)})")

        return {
            "records": records,
            "total_count": len(all_records),
            "chain_integrity": engine.verify_chain_integrity(),
            "current_hash": engine.get_current_hash()
        }

    except Exception as e:
        logger.exception(f"Error retrieving ledger: {str(e)}")
        return JSONResponse(status_code=500, content={"error": True, "detail": "Error retrieving ledger", "exception": str(e)})


@app.get("/health", response_model=HealthResponseModel, tags=["Health"])
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.
    
    Returns:
    - status: Service health status
    - ledger_size: Number of audit records
    - chain_integrity: SHA-256 chain integrity check
    """
    try:
        engine = get_dil_engine()
        return {
            "status": "healthy",
            "service": "DIL API",
            "ledger_size": engine.get_ledger_size(),
            "chain_integrity": engine.verify_chain_integrity()
        }
    except Exception as e:
        logger.exception(f"Health check failed: {str(e)}")
        return JSONResponse(status_code=503, content={"error": True, "detail": "Service unavailable", "exception": str(e)})


@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def serve_dashboard() -> str:
    """Serve the frontend dashboard"""
    try:
        # Try to load from file
        dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "index.html")
        if os.path.exists(dashboard_path):
            with open(dashboard_path, "r") as f:
                return f.read()
        else:
            # Fallback: return minimal dashboard
            return get_default_dashboard()
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        return get_default_dashboard()


# ─────────────────────────────────────────────────────────────────────────────
# MIDDLEWARE & ERROR HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """Add request ID to logs"""
    request_id = request.headers.get("X-Request-ID", "N/A")
    logger.info(f">> {request.method} {request.url.path} | Request-ID: {request_id}")
    response = await call_next(request)
    logger.info(f"<< {response.status_code} | Request-ID: {request_id}")
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler returning JSONResponse"""
    logger.error(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(status_code=exc.status_code, content={
        "error": True,
        "status_code": exc.status_code,
        "detail": exc.detail
    })


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler that returns JSON to the frontend."""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(status_code=500, content={
        "error": True,
        "detail": "Internal server error",
        "exception": str(exc)
    })


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_default_dashboard() -> str:
    """Return minimal dashboard HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DIL - Deterministic Integrity Layer</title>
        <link rel="stylesheet" href="https://cdn.tailwindcss.com">
    </head>
    <body class="bg-gray-900 text-white">
        <div class="container mx-auto p-8">
            <h1 class="text-4xl font-bold mb-4">DIL API Running</h1>
            <p class="text-gray-300 mb-4">Load index.html from the server root to use the dashboard.</p>
            <p class="text-gray-400">Available endpoints:</p>
            <ul class="list-disc ml-8 text-gray-300">
                <li>POST /audit - Process audit</li>
                <li>GET /ledger - View ledger</li>
                <li>GET /health - Health check</li>
                <li>GET /docs - Swagger UI</li>
            </ul>
        </div>
    </body>
    </html>
    """


# Vercel serverless function handler
def handler(request):
    return app(request)
