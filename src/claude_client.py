import asyncio
import json
import logging
import random
import time
from typing import Optional

import anthropic
from anthropic import AsyncAnthropic

from src.schema import ClassificationResponse, GeminiPromptData

logger = logging.getLogger(__name__)


class ClaudeClient:
    """Client for Claude Sonnet 4 API with retry logic and timeout handling."""

    def __init__(self, api_key: str, model_name: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key
        self.model_name = model_name
        self.timeout = 30.0  # 30 seconds for complex analysis
        self.max_retries = 2
        self.max_tokens = 1000  # Response tokens

        # Initialize Claude client
        self.client = AsyncAnthropic(api_key=api_key)
        logger.info(f"Claude configured with model: {model_name}")

    async def classify_email(
        self, prompt_data: GeminiPromptData
    ) -> Optional[ClassificationResponse]:
        """
        Classify email using Claude Sonnet 4 with retry logic.

        Returns:
            ClassificationResponse or None if all retries failed
        """
        start_time = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                # Calculate remaining budget
                elapsed = time.time() - start_time
                remaining_budget = prompt_data.latency_budget_ms / 1000 - elapsed

                if remaining_budget < 0.3:  # Need at least 300ms
                    logger.warning("Insufficient time budget for Claude call")
                    return None

                # Build prompts
                system_prompt = self._build_system_prompt()
                user_prompt = self._build_user_prompt(prompt_data)

                # Make API call with timeout
                response = await asyncio.wait_for(
                    self._make_claude_request(system_prompt, user_prompt),
                    timeout=min(remaining_budget, self.timeout),
                )

                if response:
                    # Parse and validate response
                    classification = self._parse_response(response)
                    if classification:
                        # Add latency info
                        classification.latency_ms = int(
                            (time.time() - start_time) * 1000
                        )
                        return classification

            except asyncio.TimeoutError:
                logger.warning(f"Claude timeout on attempt {attempt + 1}")
                if attempt < self.max_retries:
                    await asyncio.sleep(0.1 + random.uniform(0, 0.2))  # Jitter
                continue

            except Exception as e:
                logger.error(
                    f"Claude error on attempt {attempt + 1}: {type(e).__name__}: {e}"
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(0.1 + random.uniform(0, 0.2))  # Jitter
                continue

        logger.error("All Claude attempts failed")
        return None

    async def _make_claude_request(
        self, system_prompt: str, user_prompt: str
    ) -> Optional[str]:
        """Make the actual Claude API request."""
        try:
            logger.info(
                f"Calling Claude Sonnet 4 with prompt length: {len(user_prompt)}"
            )
            
            response = await self.client.messages.create(
                model=self.model_name,
                max_tokens=self.max_tokens,
                temperature=0.1,
                system=system_prompt,
                messages=[
                    {
                        "role": "user",
                        "content": user_prompt
                    }
                ]
            )
            
            logger.info(f"Claude Sonnet 4 response received: {type(response)}")

            if response.content and len(response.content) > 0:
                # Claude returns a list of content blocks
                content_block = response.content[0]
                if hasattr(content_block, 'text'):
                    return content_block.text
                else:
                    logger.warning(f"Claude response block has no text: {content_block}")
            else:
                logger.warning(f"Claude response has no content: {response}")

            return None

        except Exception as e:
            logger.error(f"Claude API request failed: {e}")
            return None

    def _build_system_prompt(self) -> str:
        """Build the system prompt for Claude."""
        return """Eres un clasificador avanzado de phishing especializado en análisis de correos electrónicos. Combinas análisis heurístico profundo y comprensión de contenido para emitir dictámenes precisos y claros para usuarios no técnicos en español neutro.

Tu objetivo principal es proteger al usuario minimizando falsos negativos: ante cualquier duda razonable, eleva la severidad de la clasificación.

CRITERIOS DE ANÁLISIS CRÍTICO:
- Suplantación de identidad y spoofing de marcas conocidas
- Urgencia financiera y presión psicológica
- Solicitudes de credenciales, contraseñas o información sensible
- Solicitudes de pagos o transferencias inmediatas
- URLs engañosas (dominios look-alike, sin HTTPS, redirecciones sospechosas)
- Fallos de autenticación (SPF/DKIM/DMARC mismatch)
- Dominios recién registrados o con bajo trust score
- Adjuntos inusuales o potencialmente maliciosos
- Errores ortográficos o gramaticales sistemáticos
- Patrones de ingeniería social y manipulación psicológica

IMPORTANTE: Nunca asumas la identidad real del remitente basándote solo en el campo "From".

RESPUESTA REQUERIDA - SOLO JSON VÁLIDO:

{
  "classification": "phishing|sospechoso|seguro",
  "risk_score": 0-100,
  "top_reasons": ["razón concisa 1", "razón concisa 2", "razón concisa 3"],
  "non_technical_summary": "≤60 palabras, explicación clara y empática para el usuario",
  "recommended_actions": ["acción específica 1", "acción específica 2"],
  "evidence": {
    "header_findings": {
      "spf_dkim_dmarc": "ok|mismatch|fail",
      "reply_to_mismatch": false,
      "display_name_spoof": false
    },
    "url_findings": [{"url":"ejemplo.com","reason":"dominio look-alike"}],
    "nlp_signals": ["señal1", "señal2"]
  }
}

REGLAS DE CLASIFICACIÓN:
- Si detectas señales críticas (URL maliciosa, solicitud de credenciales, fallo DMARC severo): ELEVA severidad
- Explica específicamente por qué una URL es riesgosa (look-alike, falta HTTPS, redirecciones, edad del dominio)
- Mantén el resumen no técnico SIN jerga y enfocado en qué debe hacer el usuario
- Si la evidencia es insuficiente: classification="sospechoso" con recomendaciones prudentes
- NUNCA devuelvas texto fuera del JSON
- Respeta el presupuesto de latencia evitando análisis excesivamente complejos

DEVUELVE ÚNICAMENTE EL JSON, SIN TEXTO ADICIONAL."""

    def _build_user_prompt(self, prompt_data: GeminiPromptData) -> str:
        """Build the user prompt with actual email data."""
        return f"""Analiza este correo electrónico para detectar phishing:

=== HEADERS DEL EMAIL (información redactada) ===
{prompt_data.headers_raw[:1000]}

=== CONTENIDO DEL MENSAJE ===
{prompt_data.text_body[:2000]}

=== FRAGMENTOS HTML RELEVANTES ===
{json.dumps(prompt_data.html_snippets[:3], ensure_ascii=False)}

=== METADATOS DE URLs DETECTADAS ===
{json.dumps(prompt_data.url_metadata[:5], ensure_ascii=False)}

=== ANÁLISIS HEURÍSTICO PREVIO ===
{prompt_data.heuristic_summary}

=== ADJUNTOS ===
Número de archivos adjuntos: {len(prompt_data.attachments_meta)}

=== CONTEXTO DEL USUARIO ===
Dominios de la organización: {prompt_data.account_context.owned_domains[:3]}
Remitentes de confianza configurados: {len(prompt_data.account_context.trusted_senders)}
Idioma del usuario: {prompt_data.account_context.user_locale}

=== RESTRICCIONES DE TIEMPO ===
Presupuesto de latencia: {prompt_data.latency_budget_ms}ms

Realiza un análisis exhaustivo y responde ÚNICAMENTE con JSON válido siguiendo el formato especificado."""

    def _parse_response(self, response_text: str) -> Optional[ClassificationResponse]:
        """Parse Claude response into ClassificationResponse."""
        try:
            # Clean response text
            response_text = response_text.strip()

            # Find JSON in response
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1

            if json_start == -1 or json_end == 0:
                logger.error("No JSON found in Claude response")
                return None

            json_text = response_text[json_start:json_end]

            # Parse JSON
            response_data = json.loads(json_text)

            # Validate required fields
            required_fields = [
                "classification",
                "risk_score",
                "top_reasons",
                "non_technical_summary",
                "recommended_actions",
                "evidence",
            ]

            for field in required_fields:
                if field not in response_data:
                    logger.error(f"Missing required field: {field}")
                    return None

            # Validate classification value
            if response_data["classification"] not in [
                "phishing",
                "sospechoso",
                "seguro",
            ]:
                logger.error(
                    f"Invalid classification: {response_data['classification']}"
                )
                return None

            # Validate risk score
            risk_score = response_data["risk_score"]
            if not isinstance(risk_score, int) or risk_score < 0 or risk_score > 100:
                logger.error(f"Invalid risk_score: {risk_score}")
                return None

            # Create response object
            classification_response = ClassificationResponse(
                classification=response_data["classification"],
                risk_score=risk_score,
                top_reasons=response_data["top_reasons"][:3],  # Limit to 3
                non_technical_summary=response_data["non_technical_summary"][
                    :200
                ],  # Limit length
                recommended_actions=response_data["recommended_actions"][
                    :3
                ],  # Limit to 3
                evidence=response_data["evidence"],
                latency_ms=0,  # Will be set by caller
            )

            return classification_response

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            logger.error(f"Response text: {response_text[:500]}")
            return None
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
            return None

    def create_fallback_response(
        self, heuristic_summary: str, risk_score: float
    ) -> ClassificationResponse:
        """Create fallback response when Claude fails."""
        # Determine classification based on risk score
        if risk_score >= 60:
            classification = "phishing"
            summary = (
                "Se detectaron múltiples señales de alto riesgo en este mensaje. "
                "Recomendamos máxima precaución y no interactuar con el contenido."
            )
            actions = [
                "No hagas clic en ningún enlace",
                "No proporciones información personal o financiera",
                "Reporta este mensaje como sospechoso",
            ]
        elif risk_score >= 40:
            classification = "sospechoso"
            summary = (
                "Este mensaje presenta características sospechosas que requieren verificación. "
                "Procede con extrema cautela antes de tomar cualquier acción."
            )
            actions = [
                "Verifica la identidad del remitente por canal oficial",
                "No hagas clic en enlaces hasta confirmar legitimidad",
                "Consulta con IT si tienes dudas",
            ]
        else:
            classification = "seguro"
            summary = (
                "No se detectaron señales significativas de riesgo en este mensaje, "
                "pero mantén siempre las precauciones generales de seguridad."
            )
            actions = [
                "El mensaje parece legítimo", 
                "Mantén precauciones generales de seguridad",
                "Verifica enlaces antes de hacer clic si tienes dudas",
            ]

        return ClassificationResponse(
            classification=classification,
            risk_score=int(risk_score),
            top_reasons=[
                "Análisis heurístico avanzado",
                "IA no disponible temporalmente",
                "Clasificación conservadora de seguridad",
            ],
            non_technical_summary=summary,
            recommended_actions=actions,
            evidence={
                "header_findings": {
                    "spf_dkim_dmarc": "ok",
                    "reply_to_mismatch": False,
                    "display_name_spoof": False,
                },
                "url_findings": [],
                "nlp_signals": ["Análisis de respaldo - Claude no disponible"],
            },
            latency_ms=0,
        )