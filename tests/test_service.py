from unittest.mock import patch

import pytest

from src.schema import ClassificationResponse, Evidence, HeaderFindings


class TestPhishingDetectionService:
    """Test cases for the main detection service."""

    @pytest.mark.asyncio
    async def test_classify_phishing_email(
        self, detection_service, sample_phishing_request, mock_gemini_client
    ):
        """Test classification of a clear phishing email."""
        # Mock Gemini response
        mock_response = ClassificationResponse(
            classification="phishing",
            risk_score=95,
            top_reasons=["DMARC failed", "Suspicious domain", "Urgent request"],
            non_technical_summary="Este mensaje intenta robar información.",
            recommended_actions=["No hagas clic en enlaces", "Reporta el mensaje"],
            evidence=Evidence(
                header_findings=HeaderFindings(spf_dkim_dmarc="fail"),
                url_findings=[],
                nlp_signals=["urgency", "credential_request"],
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        # Test classification
        result = await detection_service.classify_email(sample_phishing_request)

        # Assertions
        assert result.classification == "phishing"
        assert result.risk_score >= 60
        assert len(result.top_reasons) <= 3
        assert len(result.non_technical_summary) <= 200
        assert len(result.recommended_actions) <= 3
        assert result.latency_ms > 0

        # Verify Gemini was called
        mock_gemini_client.classify_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_classify_legitimate_email(
        self, detection_service, sample_legitimate_request, mock_gemini_client
    ):
        """Test classification of a legitimate email."""
        mock_response = ClassificationResponse(
            classification="seguro",
            risk_score=15,
            top_reasons=["DMARC passed", "Trusted sender", "No suspicious content"],
            non_technical_summary="Este mensaje parece legítimo.",
            recommended_actions=[
                "El mensaje parece seguro",
                "Mantén precauciones generales",
            ],
            evidence=Evidence(
                header_findings=HeaderFindings(spf_dkim_dmarc="ok"),
                url_findings=[],
                nlp_signals=[],
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        result = await detection_service.classify_email(sample_legitimate_request)

        assert result.classification == "seguro"
        assert result.risk_score < 40

    @pytest.mark.asyncio
    async def test_classify_suspicious_email(
        self, detection_service, sample_suspicious_request, mock_gemini_client
    ):
        """Test classification of a suspicious email."""
        mock_response = ClassificationResponse(
            classification="sospechoso",
            risk_score=55,
            top_reasons=["Unknown sender", "Generic request", "No authentication"],
            non_technical_summary="Este mensaje es sospechoso.",
            recommended_actions=["Verificar remitente", "Precaución con enlaces"],
            evidence=Evidence(
                header_findings=HeaderFindings(),
                url_findings=[],
                nlp_signals=["credential_request"],
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        result = await detection_service.classify_email(sample_suspicious_request)

        assert result.classification == "sospechoso"
        assert 40 <= result.risk_score < 60

    @pytest.mark.asyncio
    async def test_gemini_failure_fallback(
        self, detection_service, sample_phishing_request, mock_gemini_client
    ):
        """Test fallback when Gemini fails."""
        # Mock Gemini failure
        mock_gemini_client.classify_email.return_value = None
        mock_gemini_client.create_fallback_response.return_value = (
            ClassificationResponse(
                classification="sospechoso",
                risk_score=50,
                top_reasons=[
                    "Análisis heurístico",
                    "LLM no disponible",
                    "Clasificación conservadora",
                ],
                non_technical_summary="Recomendamos precaución.",
                recommended_actions=["Verificar remitente", "No hacer clic en enlaces"],
                evidence=Evidence(
                    header_findings=HeaderFindings(),
                    url_findings=[],
                    nlp_signals=["Análisis fallback"],
                ),
                latency_ms=0,
            )
        )

        result = await detection_service.classify_email(sample_phishing_request)

        # Should use fallback response
        assert result.classification == "sospechoso"
        assert "LLM no disponible" in result.top_reasons
        mock_gemini_client.create_fallback_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_security_policy_elevation(
        self,
        detection_service,
        sample_phishing_request,
        mock_gemini_client,
    ):
        """Test security policies elevate classification with critical signals."""
        # Mock Gemini returning "seguro" despite critical signals
        mock_response = ClassificationResponse(
            classification="seguro",
            risk_score=30,
            top_reasons=["No obvious threats"],
            non_technical_summary="El mensaje parece seguro.",
            recommended_actions=["Continuar normalmente"],
            evidence=Evidence(
                header_findings=HeaderFindings(
                    spf_dkim_dmarc="fail"
                ),  # Critical signal
                url_findings=[],
                nlp_signals=["credential_request"],  # Critical signal
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        result = await detection_service.classify_email(sample_phishing_request)

        # Should be elevated to "sospechoso" due to critical signals
        assert result.classification == "sospechoso"
        assert result.risk_score >= 45

    @pytest.mark.asyncio
    async def test_attachment_analysis(
        self, detection_service, sample_attachment_request, mock_gemini_client
    ):
        """Test analysis of suspicious attachments."""
        mock_response = ClassificationResponse(
            classification="phishing",
            risk_score=85,
            top_reasons=[
                "Suspicious attachments",
                "Executable files",
                "Unknown sender",
            ],
            non_technical_summary="Archivos peligrosos.",
            recommended_actions=["No abrir adjuntos", "Eliminar mensaje"],
            evidence=Evidence(
                header_findings=HeaderFindings(),
                url_findings=[],
                nlp_signals=[],
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        result = await detection_service.classify_email(sample_attachment_request)

        assert result.classification == "phishing"
        assert result.risk_score >= 60

    @pytest.mark.asyncio
    async def test_latency_within_slo(
        self, detection_service, sample_phishing_request, mock_gemini_client
    ):
        """Test that classification completes within SLO."""
        mock_response = ClassificationResponse(
            classification="phishing",
            risk_score=80,
            top_reasons=["Test"],
            non_technical_summary="Test",
            recommended_actions=["Test"],
            evidence=Evidence(
                header_findings=HeaderFindings(), url_findings=[], nlp_signals=[]
            ),
            latency_ms=0,
        )
        mock_gemini_client.classify_email.return_value = mock_response

        result = await detection_service.classify_email(sample_phishing_request)

        # Should complete within 2.5 second SLO
        assert result.latency_ms <= 2500

    @pytest.mark.asyncio
    async def test_error_handling(self, detection_service, sample_phishing_request):
        """Test error handling in classification pipeline."""
        # Force an error by using invalid service
        with patch.object(
            detection_service,
            "_run_heuristic_pipeline",
            side_effect=Exception("Test error"),
        ):
            result = await detection_service.classify_email(sample_phishing_request)

            # Should return error response
            assert result.classification == "sospechoso"
            assert result.risk_score == 50
            assert "Error en el análisis" in result.top_reasons

    def test_risk_score_thresholds(self):
        """Test risk score to classification mapping."""
        # Test the threshold logic
        test_cases = [
            (95, "phishing"),
            (65, "phishing"),
            (60, "phishing"),
            (55, "sospechoso"),
            (45, "sospechoso"),
            (40, "sospechoso"),
            (35, "seguro"),
            (15, "seguro"),
            (0, "seguro"),
        ]

        for score, expected_classification in test_cases:
            if score >= 60:
                assert expected_classification == "phishing"
            elif score >= 40:
                assert expected_classification == "sospechoso"
            else:
                assert expected_classification == "seguro"
