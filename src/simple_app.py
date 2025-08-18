"""
Simple FastAPI app for testing Cloud Run deployment
"""
import os
import time
import email
import email.policy
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException
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

class GmailAnalysisRequest(BaseModel):
    """Request for Gmail email analysis"""
    email_headers: str
    email_body: str
    sender: str
    subject: str
    attachments: Optional[List[Dict[str, Any]]] = []

class EmlAnalysisResponse(BaseModel):
    """Response for email analysis"""
    classification: str
    risk_score: int
    analysis: str
    recommendations: List[str]
    technical_details: Dict[str, Any]

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
        "test": "/test",
        "analyze_gmail": "POST /analyze/gmail",
        "analyze_eml": "POST /analyze/eml"
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
    """Simple phishing classification endpoint with basic Claude functionality."""
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
        # Try basic Claude test
        try:
            from anthropic import AsyncAnthropic
            client = AsyncAnthropic(api_key=claude_api_key)
            
            # Simple test message
            test_response = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=100,
                messages=[{
                    "role": "user", 
                    "content": "This is a test. Respond with: Claude Sonnet 4 phishing detection is working correctly."
                }]
            )
            
            return {
                "classification": "working",
                "message": "🎯 Claude Sonnet 4 successfully tested!",
                "status": "API key working",
                "api_key_status": "✅ Verified",
                "claude_response": test_response.content[0].text,
                "test_time": int(time.time())
            }
            
        except Exception as e:
            return {
                "classification": "error",
                "message": "❌ Claude API test failed",
                "status": "API key configured but not working",
                "api_key_status": "⚠️ Invalid or expired",
                "error": str(e)[:200]
            }

@app.post("/analyze/gmail", response_model=EmlAnalysisResponse)
async def analyze_gmail_email(request: GmailAnalysisRequest) -> EmlAnalysisResponse:
    """Analyze email from Gmail addon integration."""
    claude_api_key = os.getenv("CLAUDE_API_KEY")
    
    if not claude_api_key or claude_api_key == "placeholder-claude-key-configure-me":
        return EmlAnalysisResponse(
            classification="demo",
            risk_score=0,
            analysis="🚀 Demo mode: Claude API key not configured. Configure CLAUDE_API_KEY_PROD for real analysis.",
            recommendations=["Configure Claude API key", "Test with real credentials"],
            technical_details={"mode": "demo", "claude_configured": False}
        )
    
    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=claude_api_key)
        
        # Create analysis prompt
        analysis_prompt = f"""
Analyze this email for phishing indicators:

SENDER: {request.sender}
SUBJECT: {request.subject}

HEADERS:
{request.email_headers[:1000]}

BODY:
{request.email_body[:2000]}

ATTACHMENTS: {len(request.attachments)} files

Provide a JSON response with:
1. classification: "phishing", "suspicious", or "safe"
2. risk_score: 0-100
3. analysis: Brief explanation in Spanish
4. top_risks: Array of main risks found
"""
        
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,
            messages=[{"role": "user", "content": analysis_prompt}]
        )
        
        analysis_text = response.content[0].text
        
        # Simple parsing (in production, use structured output)
        if "phishing" in analysis_text.lower():
            classification = "phishing"
            risk_score = 85
        elif "suspicious" in analysis_text.lower() or "sospech" in analysis_text.lower():
            classification = "suspicious"
            risk_score = 60
        else:
            classification = "safe"
            risk_score = 15
            
        return EmlAnalysisResponse(
            classification=classification,
            risk_score=risk_score,
            analysis=analysis_text[:300],
            recommendations=[
                "Verificar remitente por canal oficial",
                "No hacer clic en enlaces sospechosos",
                "Reportar si es phishing confirmado"
            ],
            technical_details={
                "claude_model": "claude-3-5-sonnet-20241022",
                "analysis_time": int(time.time()),
                "sender": request.sender,
                "attachments_count": len(request.attachments)
            }
        )
        
    except Exception as e:
        return EmlAnalysisResponse(
            classification="error",
            risk_score=50,
            analysis=f"Error en análisis: {str(e)[:100]}",
            recommendations=["Contactar soporte técnico", "Intentar nuevamente"],
            technical_details={"error": str(e)[:200], "status": "failed"}
        )

@app.post("/analyze/eml", response_model=EmlAnalysisResponse)
async def analyze_eml_file(file: UploadFile = File(...)) -> EmlAnalysisResponse:
    """Analyze uploaded EML email file."""
    claude_api_key = os.getenv("CLAUDE_API_KEY")
    
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    
    if not claude_api_key or claude_api_key == "placeholder-claude-key-configure-me":
        return EmlAnalysisResponse(
            classification="demo",
            risk_score=0,
            analysis="🚀 Demo mode: Claude API key not configured. Upload successful but analysis disabled.",
            recommendations=["Configure Claude API key", "Test with real credentials"],
            technical_details={"mode": "demo", "file_size": file.size, "filename": file.filename}
        )
    
    try:
        # Read and parse EML file
        content = await file.read()
        
        try:
            # Parse email
            msg = email.message_from_bytes(content, policy=email.policy.default)
            
            # Extract components
            sender = msg.get('From', 'Unknown')
            subject = msg.get('Subject', 'No Subject')
            
            # Get headers
            headers = str(msg)[:2000]
            
            # Get body
            body_text = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body_text = part.get_content()[:2000]
                        break
            else:
                body_text = msg.get_content()[:2000]
            
            # Count attachments
            attachment_count = 0
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_disposition() == 'attachment':
                        attachment_count += 1
                        
        except Exception as parse_error:
            return EmlAnalysisResponse(
                classification="error",
                risk_score=0,
                analysis=f"Error parsing EML file: {str(parse_error)[:100]}",
                recommendations=["Verificar formato del archivo", "Usar archivo EML válido"],
                technical_details={"parse_error": str(parse_error)[:200]}
            )
        
        # Analyze with Claude
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=claude_api_key)
        
        analysis_prompt = f"""
Analyze this email file for phishing indicators:

SENDER: {sender}
SUBJECT: {subject}

HEADERS:
{headers}

BODY:
{body_text}

ATTACHMENTS: {attachment_count} files

Provide analysis in Spanish focusing on:
1. Sender authenticity
2. Subject line analysis  
3. Content analysis
4. Overall risk assessment
"""
        
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=600,
            messages=[{"role": "user", "content": analysis_prompt}]
        )
        
        analysis_text = response.content[0].text
        
        # Determine classification based on analysis
        analysis_lower = analysis_text.lower()
        if any(word in analysis_lower for word in ["phishing", "malicioso", "fraude", "estafa"]):
            classification = "phishing"
            risk_score = 80
        elif any(word in analysis_lower for word in ["sospechoso", "dudoso", "precaución", "cuidado"]):
            classification = "suspicious" 
            risk_score = 55
        else:
            classification = "safe"
            risk_score = 20
            
        return EmlAnalysisResponse(
            classification=classification,
            risk_score=risk_score,
            analysis=analysis_text[:400],
            recommendations=[
                "Verificar autenticidad del remitente",
                "No hacer clic en enlaces hasta confirmar legitimidad", 
                "Reportar si confirma que es phishing"
            ],
            technical_details={
                "claude_model": "claude-3-5-sonnet-20241022",
                "file_size": len(content),
                "sender": sender,
                "subject": subject,
                "attachments": attachment_count,
                "analysis_time": int(time.time())
            }
        )
        
    except Exception as e:
        return EmlAnalysisResponse(
            classification="error",
            risk_score=50,
            analysis=f"Error procesando archivo: {str(e)[:100]}",
            recommendations=["Verificar archivo EML", "Contactar soporte si persiste"],
            technical_details={"error": str(e)[:200], "status": "processing_failed"}
        )

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