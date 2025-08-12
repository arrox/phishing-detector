import asyncio
import json
import time
import random
from typing import Dict, Any, Optional
import logging
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from src.schema import ClassificationResponse, GeminiPromptData

logger = logging.getLogger(__name__)


class GeminiClient:
    """Client for Gemini 2.5 API with retry logic and timeout handling."""
    
    def __init__(self, api_key: str, model_name: str = "gemini-2.5-pro"):
        self.api_key = api_key
        self.model_name = model_name
        self.timeout = 1.2  # 1200ms
        self.max_retries = 1
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # Safety settings - allow all content for security analysis
        self.safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
        
        # Generation config for consistent results
        self.generation_config = {
            "temperature": 0.1,
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 1000,
        }
        
        # Initialize model
        self.model = genai.GenerativeModel(
            model_name=model_name,
            generation_config=self.generation_config,
            safety_settings=self.safety_settings
        )
    
    async def classify_email(self, prompt_data: GeminiPromptData) -> Optional[ClassificationResponse]:
        """
        Classify email using Gemini with retry logic.
        
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
                    logger.warning("Insufficient time budget for Gemini call")
                    return None
                
                # Build prompt
                system_prompt = self._build_system_prompt()
                user_prompt = self._build_user_prompt(prompt_data)
                
                # Make API call with timeout
                response = await asyncio.wait_for(
                    self._make_gemini_request(system_prompt, user_prompt),
                    timeout=min(remaining_budget, self.timeout)
                )
                
                if response:
                    # Parse and validate response
                    classification = self._parse_response(response)
                    if classification:
                        # Add latency info
                        classification.latency_ms = int((time.time() - start_time) * 1000)
                        return classification
                
            except asyncio.TimeoutError:
                logger.warning(f"Gemini timeout on attempt {attempt + 1}")
                if attempt < self.max_retries:
                    await asyncio.sleep(0.1 + random.uniform(0, 0.2))  # Jitter
                continue
                
            except Exception as e:
                logger.error(f"Gemini error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(0.1 + random.uniform(0, 0.2))  # Jitter
                continue
        
        logger.error("All Gemini attempts failed")
        return None
    
    async def _make_gemini_request(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Make the actual Gemini API request."""
        try:
            # Combine system and user prompts
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            
            # Generate response
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                self.model.generate_content,
                full_prompt
            )
            
            if response.candidates and len(response.candidates) > 0:
                return response.candidates[0].content.parts[0].text
            
            return None
            
        except Exception as e:
            logger.error(f"Gemini API request failed: {e}")
            return None
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt for Gemini."""
        return """Eres un clasificador de phishing. Combinas señales heurísticas y de contenido para emitir un dictamen claro para personas no técnicas en español neutro. Tu objetivo es minimizar falsos negativos (proteger al usuario): ante duda razonable, eleva la severidad.

Considera: suplantación de identidad, urgencia financiera, solicitud de credenciales o pagos, URLs engañosas (look-alike, sin HTTPS, redirecciones), misalignment SPF/DKIM/DMARC, dominio recién creado, adjuntos inusuales, errores léxicos, spoofing de marca y patrones de ingeniería social. No supongas identidad real del remitente. Ajusta tu razonamiento al budget de latencia.

DEVUELVE SOLO JSON VÁLIDO:

{
  "classification": "phishing|sospechoso|seguro",
  "risk_score": 0-100,
  "top_reasons": ["razón breve 1", "razón breve 2", "razón breve 3"],
  "non_technical_summary": "≤60 palabras, claro y empático",
  "recommended_actions": ["acción 1", "acción 2"],
  "evidence": {
    "header_findings": {"spf_dkim_dmarc": "ok|mismatch|fail", "reply_to_mismatch": false, "display_name_spoof": false},
    "url_findings": [{"url":"...","reason":"..."}],
    "nlp_signals": ["...","..."]
  }
}

Restricciones:
- Si hay señales críticas (URL dudosa, solicitud de credenciales, misalignment DMARC), ELEVA severidad
- Explica por qué una URL es riesgosa (look-alike, sin HTTPS, redirecciones, edad de dominio)
- Mantén non_technical_summary SIN tecnicismos y centrado en qué hacer
- Si evidencia insuficiente → classification="sospechoso" con recomendaciones prudentes
- Nunca devuelvas texto fuera del JSON
- Respeta latency_budget_ms (evita cadenas de razonamiento largas)"""
    
    def _build_user_prompt(self, prompt_data: GeminiPromptData) -> str:
        """Build the user prompt with actual data."""
        return f"""Analiza este email:

HEADERS (redactados):
{prompt_data.headers_raw[:1000]}

CONTENIDO:
{prompt_data.text_body[:2000]}

HTML SNIPPETS:
{json.dumps(prompt_data.html_snippets[:3], ensure_ascii=False)}

METADATOS DE URLs:
{json.dumps(prompt_data.url_metadata[:5], ensure_ascii=False)}

RESUMEN HEURÍSTICO:
{prompt_data.heuristic_summary}

ADJUNTOS:
{len(prompt_data.attachments_meta)} archivos: {[f['filename'] + ' (' + f['mime'] + ')' for f in prompt_data.attachments_meta[:3]]}

CONTEXTO:
Dominios propios: {prompt_data.account_context.owned_domains[:3]}
Remitentes confiables: {len(prompt_data.account_context.trusted_senders)} configurados
Locale: {prompt_data.account_context.user_locale}

Budget de latencia: {prompt_data.latency_budget_ms}ms

Clasifica y responde SOLO con JSON válido."""
    
    def _parse_response(self, response_text: str) -> Optional[ClassificationResponse]:
        """Parse Gemini response into ClassificationResponse."""
        try:
            # Clean response text
            response_text = response_text.strip()
            
            # Find JSON in response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                logger.error("No JSON found in Gemini response")
                return None
            
            json_text = response_text[json_start:json_end]
            
            # Parse JSON
            response_data = json.loads(json_text)
            
            # Validate required fields
            required_fields = ['classification', 'risk_score', 'top_reasons', 
                             'non_technical_summary', 'recommended_actions', 'evidence']
            
            for field in required_fields:
                if field not in response_data:
                    logger.error(f"Missing required field: {field}")
                    return None
            
            # Validate classification value
            if response_data['classification'] not in ['phishing', 'sospechoso', 'seguro']:
                logger.error(f"Invalid classification: {response_data['classification']}")
                return None
            
            # Validate risk score
            risk_score = response_data['risk_score']
            if not isinstance(risk_score, int) or risk_score < 0 or risk_score > 100:
                logger.error(f"Invalid risk_score: {risk_score}")
                return None
            
            # Create response object
            classification_response = ClassificationResponse(
                classification=response_data['classification'],
                risk_score=risk_score,
                top_reasons=response_data['top_reasons'][:3],  # Limit to 3
                non_technical_summary=response_data['non_technical_summary'][:200],  # Limit length
                recommended_actions=response_data['recommended_actions'][:3],  # Limit to 3
                evidence=response_data['evidence'],
                latency_ms=0  # Will be set by caller
            )
            
            return classification_response
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            logger.error(f"Response text: {response_text[:500]}")
            return None
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
            return None
    
    def create_fallback_response(self, heuristic_summary: str, risk_score: float) -> ClassificationResponse:
        """Create fallback response when Gemini fails."""
        # Determine classification based on risk score
        if risk_score >= 60:
            classification = "phishing"
            summary = "Se detectaron múltiples señales de riesgo en este mensaje. Recomendamos precaución."
            actions = ["No hagas clic en enlaces", "No proporciones información personal"]
        elif risk_score >= 40:
            classification = "sospechoso"
            summary = "Este mensaje presenta algunas características sospechosas. Verifica antes de actuar."
            actions = ["Verifica el remitente por canal oficial", "Ten precaución con los enlaces"]
        else:
            classification = "seguro"
            summary = "No se detectaron señales significativas de riesgo en este mensaje."
            actions = ["El mensaje parece legítimo", "Mantén precauciones generales"]
        
        return ClassificationResponse(
            classification=classification,
            risk_score=int(risk_score),
            top_reasons=["Análisis heurístico", "LLM no disponible", "Clasificación conservadora"],
            non_technical_summary=summary,
            recommended_actions=actions,
            evidence={
                "header_findings": {"spf_dkim_dmarc": "ok", "reply_to_mismatch": False, "display_name_spoof": False},
                "url_findings": [],
                "nlp_signals": ["Análisis fallback"]
            },
            latency_ms=0
        )