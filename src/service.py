import asyncio
import logging
import time
from typing import Any, Dict, List

import structlog

from src.gemini_client import GeminiClient
from src.header_analysis import HeaderAnalyzer
from src.nlp_features import NLPAnalyzer
from src.redaction import PIIRedactor
from src.schema import (
    ClassificationRequest,
    ClassificationResponse,
    Evidence,
    GeminiPromptData,
    HeaderFindings,
    HeuristicFeatures,
    URLFinding,
)
from src.url_analysis import URLAnalyzer

# Setup structured logging
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
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class PhishingDetectionService:
    """Main service orchestrating the phishing detection pipeline."""

    def __init__(self, gemini_api_key: str):
        self.redactor = PIIRedactor()
        self.header_analyzer = HeaderAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.nlp_analyzer = NLPAnalyzer()
        self.gemini_client = GeminiClient(gemini_api_key)

        # SLO targets
        self.target_latency_ms = (
            35000  # 35s target for complete analysis including Gemini 2.5 Pro
        )
        self.heuristic_budget_ms = 700  # Budget for heuristic pipeline
        self.gemini_budget_ms = 1200  # Budget for Gemini call

    async def classify_email(
        self, request: ClassificationRequest
    ) -> ClassificationResponse:
        """
        Main classification pipeline.

        Returns:
            ClassificationResponse with phishing classification
        """
        start_time = time.time()
        request_id = f"req_{int(start_time * 1000000) % 1000000}"

        logger.info(
            "Starting email classification",
            request_id=request_id,
            has_html=bool(request.raw_html),
            has_text=bool(request.text_body),
            has_headers=bool(request.raw_headers),
            attachments_count=len(request.attachments_meta),
        )

        try:
            # Step 1: Run heuristic pipeline (parallel execution)
            heuristic_features = await self._run_heuristic_pipeline(request, request_id)

            heuristic_time = time.time() - start_time
            logger.info(
                "Heuristic pipeline completed",
                request_id=request_id,
                latency_ms=int(heuristic_time * 1000),
                total_score=heuristic_features.total_score,
            )

            # Step 2: Prepare data for Gemini
            prompt_data = self._prepare_gemini_prompt(request, heuristic_features)

            # Step 3: Call Gemini with remaining budget
            remaining_budget = self.target_latency_ms - (heuristic_time * 1000)
            prompt_data.latency_budget_ms = max(
                int(remaining_budget), 30000
            )  # Minimum 30s for Gemini 2.5 Pro

            gemini_response = await self.gemini_client.classify_email(prompt_data)

            # Step 4: Fallback if Gemini fails
            if not gemini_response:
                logger.warning(
                    "Gemini classification failed, using fallback",
                    request_id=request_id,
                )
                gemini_response = self._create_fallback_response(heuristic_features)

            # Step 5: Apply security policies and finalize response
            final_response = self._apply_security_policies(
                gemini_response, heuristic_features
            )

            # Add final latency
            total_time = time.time() - start_time
            final_response.latency_ms = int(total_time * 1000)

            # Log final classification
            logger.info(
                "Email classification completed",
                request_id=request_id,
                classification=final_response.classification,
                risk_score=final_response.risk_score,
                latency_ms=final_response.latency_ms,
                within_slo=final_response.latency_ms <= self.target_latency_ms,
            )

            return final_response

        except Exception as e:
            error_time = int((time.time() - start_time) * 1000)
            logger.error(
                "Email classification failed",
                request_id=request_id,
                error=str(e),
                latency_ms=error_time,
            )

            # Return safe fallback
            return self._create_error_response(error_time)

    async def _run_heuristic_pipeline(
        self, request: ClassificationRequest, request_id: str
    ) -> HeuristicFeatures:
        """Run the heuristic analysis pipeline in parallel."""

        # Redact PII first
        redacted_headers = self.redactor.redact_headers(request.raw_headers)
        redacted_text, text_hashes = self.redactor.redact_text(request.text_body)
        html_snippets = self.redactor.extract_safe_snippets(request.text_body)

        logger.debug(
            "PII redaction completed",
            request_id=request_id,
            text_redactions=len(text_hashes),
        )

        # Run analyses in parallel
        tasks = [
            self._analyze_headers(redacted_headers, request_id),
            self._analyze_urls(request.raw_html, redacted_text, request_id),
            self._analyze_nlp(redacted_text, request_id),
            self._analyze_attachments(request.attachments_meta, request_id),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        header_result = (
            results[0]
            if not isinstance(results[0], Exception)
            else (HeaderFindings(), {}, 0.0)
        )
        url_result = (
            results[1] if not isinstance(results[1], Exception) else ([], [], 0.0)
        )
        nlp_result = (
            results[2] if not isinstance(results[2], Exception) else (None, [], 0.0)
        )
        attachment_result = results[3] if not isinstance(results[3], Exception) else 0.0

        # Combine scores
        header_score = header_result[2]
        url_score = url_result[2]
        nlp_score = nlp_result[2]
        attachment_score = attachment_result

        total_score = (
            header_score * 0.3
            + url_score * 0.4
            + nlp_score * 0.25
            + attachment_score * 0.05
        )

        return HeuristicFeatures(
            header_score=header_score,
            url_score=url_score,
            nlp_score=nlp_score,
            attachment_score=attachment_score,
            total_score=total_score,
            signals={
                "header_findings": header_result[0],
                "header_details": header_result[1],
                "url_findings": url_result[0],
                "url_metadata": url_result[1],
                "nlp_signals": nlp_result[1],
                "attachment_risks": [],
            },
        )

    async def _analyze_headers(self, headers: str, request_id: str) -> tuple:
        """Analyze email headers."""
        try:
            findings, details = self.header_analyzer.analyze_headers(headers)
            score = self.header_analyzer.calculate_header_risk_score(findings)
            return findings, details, score
        except Exception as e:
            logger.error("Header analysis failed", request_id=request_id, error=str(e))
            return HeaderFindings(), {}, 0.0

    async def _analyze_urls(self, html: str, text: str, request_id: str) -> tuple:
        """Analyze URLs in email content."""
        try:
            findings, metadata = await self.url_analyzer.analyze_urls(html, text)
            score = self.url_analyzer.calculate_url_risk_score(findings)
            return findings, metadata, score
        except Exception as e:
            logger.error("URL analysis failed", request_id=request_id, error=str(e))
            return [], [], 0.0

    async def _analyze_nlp(self, text: str, request_id: str) -> tuple:
        """Analyze text content for NLP signals."""
        try:
            signals, descriptions = self.nlp_analyzer.analyze_text(text)
            score = self.nlp_analyzer.calculate_nlp_risk_score(signals)
            return signals, descriptions, score
        except Exception as e:
            logger.error("NLP analysis failed", request_id=request_id, error=str(e))
            return None, [], 0.0

    async def _analyze_attachments(
        self, attachments: List[Dict], request_id: str
    ) -> float:
        """Analyze attachment metadata for risks."""
        try:
            if not attachments:
                return 0.0

            risk_score = 0.0
            risky_extensions = {
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".com",
                ".pif",
                ".zip",
                ".rar",
            }

            for attachment in attachments:
                filename = attachment.get("filename", "").lower()
                mime = attachment.get("mime", "").lower()
                size = attachment.get("size", 0)

                # Check extension
                if any(filename.endswith(ext) for ext in risky_extensions):
                    risk_score += 25.0

                # Check for executable MIME types
                if "executable" in mime or "application/x-" in mime:
                    risk_score += 15.0

                # Unusual size patterns
                if size > 50 * 1024 * 1024:  # >50MB
                    risk_score += 5.0
                elif size == 0:  # Empty file
                    risk_score += 10.0

            return min(risk_score, 100.0)

        except Exception as e:
            logger.error(
                "Attachment analysis failed", request_id=request_id, error=str(e)
            )
            return 0.0

    def _prepare_gemini_prompt(
        self, request: ClassificationRequest, features: HeuristicFeatures
    ) -> GeminiPromptData:
        """Prepare data for Gemini prompt."""

        # Create heuristic summary
        summary_parts = []

        if features.header_score > 20:
            summary_parts.append(f"Headers: riesgo {features.header_score:.0f}/100")

        if features.url_score > 20:
            url_count = len(features.signals.get("url_findings", []))
            summary_parts.append(
                f"URLs: {url_count} sospechosas, riesgo {features.url_score:.0f}/100"
            )

        if features.nlp_score > 20:
            nlp_signals = features.signals.get("nlp_signals", [])
            summary_parts.append(
                f"NLP: {len(nlp_signals)} señales, riesgo {features.nlp_score:.0f}/100"
            )

        if features.attachment_score > 10:
            summary_parts.append(
                f"Adjuntos: riesgo {features.attachment_score:.0f}/100"
            )

        heuristic_summary = (
            "; ".join(summary_parts) if summary_parts else "Sin señales significativas"
        )

        return GeminiPromptData(
            headers_raw=self.redactor.redact_headers(request.raw_headers),
            text_body=request.text_body[:2000],  # Limit text length
            html_snippets=self.redactor.extract_safe_snippets(request.text_body),
            attachments_meta=request.attachments_meta,
            url_metadata=features.signals.get("url_metadata", []),
            heuristic_summary=heuristic_summary,
            account_context=request.account_context,
        )

    def _apply_security_policies(
        self, response: ClassificationResponse, features: HeuristicFeatures
    ) -> ClassificationResponse:
        """Apply security policies to ensure safe classification."""

        # Policy 1: Critical signals force elevation
        critical_signals = []

        # Check for critical header issues
        header_findings = features.signals.get("header_findings")
        if header_findings and header_findings.spf_dkim_dmarc == "fail":
            critical_signals.append("DMARC failure")

        # Check for high-risk URLs
        url_findings = features.signals.get("url_findings", [])
        high_risk_urls = [
            f for f in url_findings if getattr(f, "risk_level", "low") == "high"
        ]
        if high_risk_urls:
            critical_signals.append("High-risk URLs")

        # Check for credential requests
        nlp_signals = features.signals.get("nlp_signals", [])
        if any("credencial" in signal.lower() for signal in nlp_signals):
            critical_signals.append("Credential request")

        # Apply elevation policy
        if critical_signals and response.classification == "seguro":
            response.classification = "sospechoso"
            response.risk_score = max(response.risk_score, 45)
            response.top_reasons.insert(
                0, f"Señales críticas: {', '.join(critical_signals[:2])}"
            )

        elif (
            critical_signals
            and response.classification == "sospechoso"
            and len(critical_signals) >= 2
        ):
            response.classification = "phishing"
            response.risk_score = max(response.risk_score, 65)

        # Policy 2: Ensure risk_score matches classification
        if response.classification == "phishing" and response.risk_score < 60:
            response.risk_score = 60
        elif response.classification == "sospechoso" and response.risk_score < 40:
            response.risk_score = 40
        elif response.classification == "seguro" and response.risk_score >= 40:
            response.classification = "sospechoso"

        return response

    def _create_fallback_response(
        self, features: HeuristicFeatures
    ) -> ClassificationResponse:
        """Create fallback response when Gemini is unavailable."""
        return self.gemini_client.create_fallback_response(
            heuristic_summary=f"Score: {features.total_score:.0f}/100",
            risk_score=features.total_score,
        )

    def _create_error_response(self, latency_ms: int) -> ClassificationResponse:
        """Create error response for system failures."""
        return ClassificationResponse(
            classification="sospechoso",
            risk_score=50,
            top_reasons=[
                "Error en el análisis",
                "Clasificación conservadora",
                "Recomendar precaución",
            ],
            non_technical_summary="No pudimos analizar completamente este mensaje. Por precaución, recomendamos verificar su legitimidad.",
            recommended_actions=[
                "Verificar remitente por canal oficial",
                "No hacer clic en enlaces",
                "Contactar soporte si es urgente",
            ],
            evidence=Evidence(
                header_findings=HeaderFindings(),
                url_findings=[],
                nlp_signals=["Error de sistema"],
            ),
            latency_ms=latency_ms,
        )
