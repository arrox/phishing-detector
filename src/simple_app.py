"""
Simple FastAPI app for testing Cloud Run deployment
"""
import os
import time
from typing import Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

# Create FastAPI app
app = FastAPI(
    title="Phishing Detection API - Test Version",
    description="Simplified version for testing Cloud Run deployment",
    version="1.0.0-test",
    docs_url="/docs",
    redoc_url="/redoc"
)

class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: int
    version: str

@app.get("/")
async def root() -> Dict[str, Any]:
    """Root endpoint with service information."""
    return {
        "service": "Phishing Detection API - Test Version",
        "status": "🚀 RUNNING SUCCESSFULLY",
        "version": "1.0.0-test",
        "environment": os.getenv("ENVIRONMENT", "not-set"),
        "message": "¡Deployment a producción exitoso! 🎉",
        "docs": "/docs",
        "health": "/health",
        "ready": "/ready",
        "test": "/test"
    }

@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint for Cloud Run."""
    return HealthResponse(
        status="healthy",
        service="phishing-detection-test",
        timestamp=int(time.time()),
        version="1.0.0-test"
    )

@app.get("/ready")
async def ready() -> Dict[str, Any]:
    """Readiness check endpoint for Cloud Run."""
    return {
        "status": "ready",
        "service": "phishing-detection-test",
        "timestamp": int(time.time()),
        "message": "Service is ready to handle requests"
    }

@app.get("/test")
async def test() -> Dict[str, Any]:
    """Test endpoint to verify functionality and environment."""
    env_vars = {
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "not-set"),
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "not-set"),
        "WORKERS": os.getenv("WORKERS", "not-set"),
        "CLAUDE_API_KEY": "✅ set" if os.getenv("CLAUDE_API_KEY") else "❌ not-set",
        "AUTH_TOKEN": "✅ set" if os.getenv("AUTH_TOKEN") else "❌ not-set",
        "HOST": os.getenv("HOST", "not-set"),
        "PORT": os.getenv("PORT", "not-set")
    }
    
    return {
        "message": "🧪 Test endpoint working perfectly!",
        "environment_variables": env_vars,
        "deployment_status": "✅ SUCCESSFUL",
        "timestamp": int(time.time()),
        "cloud_run": "✅ RUNNING"
    }

@app.get("/ping")
async def ping() -> Dict[str, str]:
    """Simple ping endpoint."""
    return {"ping": "pong", "status": "ok"}

@app.post("/classify")
async def classify_simple() -> Dict[str, Any]:
    """Simple phishing classification endpoint (demo)."""
    claude_api_key = os.getenv("CLAUDE_API_KEY")
    
    if not claude_api_key or claude_api_key == "placeholder-claude-key-configure-me":
        return {
            "classification": "demo",
            "message": "🚀 Claude Sonnet 4 migration successful!",
            "status": "API key not configured - demo mode",
            "instructions": "Configure CLAUDE_API_KEY_PROD secret for full functionality",
            "improvements": [
                "Upgraded from Gemini to Claude Sonnet 4",
                "Enhanced phishing detection capabilities",
                "Improved analysis prompts",
                "Better security recommendations"
            ]
        }
    else:
        return {
            "classification": "ready",
            "message": "🎯 Claude Sonnet 4 ready for advanced phishing analysis!",
            "status": "Configured and ready",
            "api_key_status": "✅ Configured"
        }

# Startup event for logging
@app.on_event("startup")
async def startup_event():
    """Log startup information."""
    print("🚀 Simple Test API starting up...")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'not-set')}")
    print(f"Port: {os.getenv('PORT', '8000')}")
    print("✅ Startup complete!")

# This section is for development only
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    print(f"🚀 Starting Simple Test API on {host}:{port}")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'not-set')}")
    print(f"Docs available at: http://{host}:{port}/docs")
    
    uvicorn.run(
        "src.simple_app:app",
        host=host,
        port=port,
        log_level="info",
        reload=False
    )