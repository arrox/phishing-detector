import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

from src.schema import ClassificationRequest, ClassificationResponse
from src.service import PhishingDetectionService

# Setup structured logging
logger = structlog.get_logger(__name__)

# Metrics
REQUEST_COUNT = Counter(
    "phishing_requests_total", "Total requests", ["method", "endpoint", "status"]
)
REQUEST_DURATION = Histogram("phishing_request_duration_seconds", "Request duration")
CLASSIFICATION_COUNT = Counter(
    "phishing_classifications_total", "Classifications by result", ["classification"]
)
ERROR_COUNT = Counter("phishing_errors_total", "Errors by type", ["error_type"])

# Global service instance
detection_service: PhishingDetectionService = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global detection_service

    # Startup
    logger.info("Starting Phishing Detection Service")

    # Initialize service with Claude API key
    claude_api_key = os.getenv("CLAUDE_API_KEY")
    if not claude_api_key:
        logger.warning("CLAUDE_API_KEY not set, using placeholder for testing")
        claude_api_key = "test-key-placeholder"

    try:
        detection_service = PhishingDetectionService(claude_api_key)
        logger.info("Service initialized successfully with Claude Sonnet 4")
    except Exception as e:
        logger.error(f"Failed to initialize service: {e}")
        # For now, allow startup to continue even if service fails
        detection_service = None
        logger.warning("Service initialization failed, continuing with limited functionality")

    yield

    # Shutdown
    logger.info("Shutting down Phishing Detection Service")


# Create FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="Microservicio de detección de phishing con análisis heurístico + "
    "Claude Sonnet 4",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Security
security = HTTPBearer(auto_error=False)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv(
        "ALLOWED_ORIGINS", "https://*.googleapis.com,https://*.google.com"
    ).split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(",")
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Validate Bearer token authentication."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # In production, validate against your auth service
    expected_token = os.getenv("API_TOKEN")
    if not expected_token:
        logger.warning("API_TOKEN not configured, skipping auth")
        return {"user_id": "anonymous"}

    # For debugging, strip any whitespace
    received_token = credentials.credentials.strip()
    expected_token = expected_token.strip()

    logger.info(
        "Auth debug - received: '%s', expected: '%s'",
        received_token,
        expected_token,
    )

    if received_token != expected_token:
        logger.warning(
            "Token mismatch - received len: %d, expected len: %d",
            len(received_token),
            len(expected_token),
        )
        logger.warning(f"Received bytes: {received_token.encode()}")
        logger.warning(f"Expected bytes: {expected_token.encode()}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"user_id": "authenticated"}


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Collect metrics for all requests."""
    start_time = time.time()

    # Process request
    response = await call_next(request)

    # Record metrics
    duration = time.time() - start_time
    REQUEST_DURATION.observe(duration)
    REQUEST_COUNT.labels(
        method=request.method, endpoint=request.url.path, status=response.status_code
    ).inc()

    # Log request
    logger.info(
        "HTTP request processed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=int(duration * 1000),
        user_agent=request.headers.get("user-agent", ""),
    )

    return response


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "phishing-detection",
        "version": "1.0.0",
        "timestamp": int(time.time()),
    }


@app.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """Readiness check endpoint."""
    if not detection_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service not ready"
        )

    return {
        "status": "ready",
        "service": "phishing-detection",
        "components": {"claude_client": "ready", "analyzers": "ready"},
    }


@app.get("/metrics")
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/classify", response_model=ClassificationResponse)
async def classify_email(
    request: ClassificationRequest, current_user: dict = Depends(get_current_user)
) -> ClassificationResponse:
    """
    Classify an email for phishing detection.

    This endpoint analyzes email headers, content, and URLs to determine
    if the email is phishing, suspicious, or safe.

    - **raw_headers**: Raw email headers as string
    - **raw_html**: HTML content of the email
    - **text_body**: Plain text content
    - **attachments_meta**: List of attachment metadata (no content)
    - **account_context**: User context for improved analysis

    Returns classification with risk score, reasons, and recommendations.
    """
    if not detection_service:
        ERROR_COUNT.labels(error_type="service_unavailable").inc()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection service not available",
        )

    try:
        # Validate request
        if not any([request.raw_headers, request.raw_html, request.text_body]):
            ERROR_COUNT.labels(error_type="invalid_request").inc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one of raw_headers, raw_html, or text_body must be "
                "provided",
            )

        # Classify email
        logger.info(
            "Processing classification request",
            user_id=current_user.get("user_id"),
            has_headers=bool(request.raw_headers),
            has_html=bool(request.raw_html),
            has_text=bool(request.text_body),
            attachments=len(request.attachments_meta),
            locale=request.account_context.user_locale,
        )

        start_time = time.time()
        response = await detection_service.classify_email(request)
        classification_time = time.time() - start_time

        # Record metrics
        CLASSIFICATION_COUNT.labels(classification=response.classification).inc()

        logger.info(
            "Classification completed",
            user_id=current_user.get("user_id"),
            classification=response.classification,
            risk_score=response.risk_score,
            latency_ms=response.latency_ms,
            processing_time_ms=int(classification_time * 1000),
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        ERROR_COUNT.labels(error_type="internal_error").inc()
        logger.error(
            "Classification failed with internal error",
            user_id=current_user.get("user_id"),
            error=str(e),
            error_type=type(e).__name__,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during classification",
        )


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Phishing Detection API",
        "version": "1.0.0",
        "description": "Microservicio de detección de phishing con análisis "
        "heurístico + Claude Sonnet 4",
        "docs_url": "/docs",
        "health_url": "/health",
        "endpoints": {
            "classify": "POST /classify - Classify email for phishing",
            "health": "GET /health - Health check",
            "ready": "GET /ready - Readiness check",
            "metrics": "GET /metrics - Prometheus metrics",
        },
    }


# Rate limiting middleware (basic implementation)
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Basic rate limiting middleware."""

    # Skip rate limiting for health checks
    if request.url.path in ["/health", "/ready", "/metrics"]:
        return await call_next(request)

    # Get client IP
    client_ip = request.client.host

    # In production, implement proper rate limiting with Redis
    # For now, just log the request
    logger.debug("Rate limit check", client_ip=client_ip, path=request.url.path)

    return await call_next(request)


if __name__ == "__main__":
    # Configuration from environment variables
    host = os.getenv("HOST", "0.0.0.0")  # Cloud Run requires 0.0.0.0
    port = int(os.getenv("PORT", "8000"))
    workers = int(os.getenv("WORKERS", "1"))
    log_level = os.getenv("LOG_LEVEL", "info").lower()

    # Debug logging for startup
    print(f"🚀 Starting Phishing Detection API")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Workers: {workers}")
    print(f"Log Level: {log_level}")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'not-set')}")
    print(f"CLAUDE_API_KEY: {'set' if os.getenv('CLAUDE_API_KEY') else 'not-set'}")
    print(f"API_TOKEN: {'set' if os.getenv('API_TOKEN') else 'not-set'}")

    # Run with Uvicorn
    try:
        uvicorn.run(
            "src.app:app",
            host=host,
            port=port,
            workers=workers,
            log_level=log_level,
            access_log=True,
            loop="asyncio",
        )
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        raise
