import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, AsyncMock, patch
import os

# Set environment variables before importing app
os.environ["GEMINI_API_KEY"] = "test-api-key"
os.environ["API_TOKEN"] = "test-token"

from src.app import app
from src.schema import ClassificationResponse, Evidence, HeaderFindings


@pytest.fixture
def client():
    """Test client for FastAPI app."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Authentication headers for requests."""
    return {"Authorization": "Bearer test-token"}


class TestPhishingAPI:
    """Test cases for the FastAPI endpoints."""

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "phishing-detection"
        assert "timestamp" in data

    def test_readiness_check(self, client):
        """Test readiness check endpoint."""
        with patch("src.app.detection_service") as mock_service:
            mock_service.__bool__ = lambda: True

            response = client.get("/ready")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert "components" in data

    def test_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "Phishing Detection API"
        assert "endpoints" in data

    def test_classify_endpoint_success(
        self, client, auth_headers, sample_phishing_request
    ):
        """Test successful email classification."""
        with patch("src.app.detection_service") as mock_service:
            # Mock service response
            mock_response = ClassificationResponse(
                classification="phishing",
                risk_score=85,
                top_reasons=["Suspicious domain", "DMARC failure", "Urgent request"],
                non_technical_summary="Este mensaje intenta robar información personal.",
                recommended_actions=["No hacer clic", "Reportar mensaje"],
                evidence=Evidence(
                    header_findings=HeaderFindings(spf_dkim_dmarc="fail"),
                    url_findings=[],
                    nlp_signals=["urgency"],
                ),
                latency_ms=1500,
            )

            mock_service.classify_email = AsyncMock(return_value=mock_response)

            response = client.post(
                "/classify", json=sample_phishing_request.dict(), headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()
            assert data["classification"] == "phishing"
            assert data["risk_score"] == 85
            assert len(data["top_reasons"]) <= 3
            assert data["latency_ms"] > 0

    def test_classify_endpoint_unauthorized(self, client, sample_phishing_request):
        """Test classification without authentication."""
        response = client.post("/classify", json=sample_phishing_request.dict())

        assert response.status_code == 401
        assert "Bearer token required" in response.json()["detail"]

    def test_classify_endpoint_invalid_token(self, client, sample_phishing_request):
        """Test classification with invalid token."""
        headers = {"Authorization": "Bearer invalid-token"}

        response = client.post(
            "/classify", json=sample_phishing_request.dict(), headers=headers
        )

        assert response.status_code == 401
        assert "Invalid authentication token" in response.json()["detail"]

    def test_classify_endpoint_missing_content(self, client, auth_headers):
        """Test classification with missing content."""
        invalid_request = {
            "raw_headers": "",
            "raw_html": "",
            "text_body": "",
            "attachments_meta": [],
            "account_context": {},
        }

        response = client.post("/classify", json=invalid_request, headers=auth_headers)

        assert response.status_code == 400
        assert "must be provided" in response.json()["detail"]

    def test_classify_endpoint_service_unavailable(
        self, client, auth_headers, sample_phishing_request
    ):
        """Test classification when service is unavailable."""
        with patch("src.app.detection_service", None):
            response = client.post(
                "/classify", json=sample_phishing_request.dict(), headers=auth_headers
            )

            assert response.status_code == 503
            assert "not available" in response.json()["detail"]

    def test_classify_endpoint_internal_error(
        self, client, auth_headers, sample_phishing_request
    ):
        """Test classification with internal error."""
        with patch("src.app.detection_service") as mock_service:
            mock_service.classify_email = AsyncMock(
                side_effect=Exception("Internal error")
            )

            response = client.post(
                "/classify", json=sample_phishing_request.dict(), headers=auth_headers
            )

            assert response.status_code == 500
            assert "Internal server error" in response.json()["detail"]

    def test_request_validation(self, client, auth_headers):
        """Test request validation with invalid data."""
        invalid_request = {
            "raw_headers": "valid headers",
            "raw_html": "<html>valid</html>",
            "text_body": "valid text",
            "attachments_meta": [
                {
                    "filename": "test.pdf",
                    "mime": "application/pdf",
                    "size": "invalid_size",  # Should be int
                    "hash": "abc123",
                }
            ],
        }

        response = client.post("/classify", json=invalid_request, headers=auth_headers)

        assert response.status_code == 422  # Validation error

    def test_cors_headers(self, client):
        """Test CORS headers are present."""
        response = client.options("/classify")

        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers

    def test_response_format(self, client, auth_headers, sample_phishing_request):
        """Test response format matches schema."""
        with patch("src.app.detection_service") as mock_service:
            mock_response = ClassificationResponse(
                classification="sospechoso",
                risk_score=55,
                top_reasons=["Test reason"],
                non_technical_summary="Test summary",
                recommended_actions=["Test action"],
                evidence=Evidence(
                    header_findings=HeaderFindings(), url_findings=[], nlp_signals=[]
                ),
                latency_ms=1000,
            )

            mock_service.classify_email = AsyncMock(return_value=mock_response)

            response = client.post(
                "/classify", json=sample_phishing_request.dict(), headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()

            # Check required fields
            required_fields = [
                "classification",
                "risk_score",
                "top_reasons",
                "non_technical_summary",
                "recommended_actions",
                "evidence",
                "latency_ms",
            ]

            for field in required_fields:
                assert field in data

            # Check value constraints
            assert data["classification"] in ["phishing", "sospechoso", "seguro"]
            assert 0 <= data["risk_score"] <= 100
            assert isinstance(data["top_reasons"], list)
            assert len(data["top_reasons"]) <= 3
            assert len(data["recommended_actions"]) <= 3
            assert isinstance(data["latency_ms"], int)
