"""
Simple FastAPI app for testing Cloud Run deployment
"""
import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(
    title="Phishing Detection API - Simple Test",
    description="Simple version for testing deployment",
    version="1.0.0-test"
)

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Phishing Detection API - Test",
        "status": "running",
        "version": "1.0.0-test",
        "environment": os.getenv("ENVIRONMENT", "not-set"),
        "message": "Deployment successful! 🎉"
    }

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "phishing-detection-test"
    }

@app.get("/ready")
async def ready():
    """Readiness check endpoint."""
    return {
        "status": "ready",
        "service": "phishing-detection-test"
    }

@app.get("/test")
async def test():
    """Test endpoint to verify functionality."""
    env_vars = {
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "not-set"),
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "not-set"),
        "WORKERS": os.getenv("WORKERS", "not-set"),
        "GEMINI_API_KEY": "set" if os.getenv("GEMINI_API_KEY") else "not-set",
        "API_TOKEN": "set" if os.getenv("API_TOKEN") else "not-set"
    }
    
    return {
        "message": "Test endpoint working!",
        "environment_variables": env_vars,
        "deployment": "successful"
    }

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    print(f"🚀 Starting Simple Test API on {host}:{port}")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'not-set')}")
    
    uvicorn.run(
        "src.simple_app:app",
        host=host,
        port=port,
        log_level="info"
    )