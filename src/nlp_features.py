import logging
import re
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class NLPSignals:
    urgency_score: float = 0.0
    credential_request: bool = False
    payment_request: bool = False
    lexical_errors: int = 0
    language_mixing: bool = False
    brand_mentions: List[str] = None
    threat_indicators: List[str] = None

    def __post_init__(self):
        if self.brand_mentions is None:
            self.brand_mentions = []
        if self.threat_indicators is None:
            self.threat_indicators = []


class NLPAnalyzer:
    """Analyzes text content for phishing indicators using NLP techniques."""

    def __init__(self):
        # Urgency indicators in Spanish and English
        self.urgency_patterns = [
            # Spanish
            r"\b(?:urgente|inmediato|rápido|ahora|ya|pronto)\b",
            r"\b(?:caduca|expira|vence|suspender|cancelar)\b",
            r"\b(?:últimas? \d+ horas?|dentro de \d+ días?)\b",
            r"\b(?:acción requerida|acción inmediata)\b",
            # English
            r"\b(?:urgent|immediate|asap|right now|quickly)\b",
            r"\b(?:expires?|suspend|cancel|terminate)\b",
            r"\b(?:within \d+ (?:hours?|days?)|last \d+ hours?)\b",
            r"\b(?:action required|immediate action)\b",
        ]

        # Credential request patterns
        self.credential_patterns = [
            # Spanish
            r"\b(?:contraseña|clave|password|pin|código)\b",
            r"\b(?:verificar|confirmar|actualizar|validar)\s+(?:cuenta|datos|"
            r"información)\b",
            r"\b(?:ingresar|introducir|proporcionar)\s+(?:sus?\s+)?(?:datos|"
            r"credenciales)\b",
            r"\b(?:hacer\s+)?(?:clic|click)\s+(?:aquí|abajo|en\s+el\s+enlace)\b",
            # English
            r"\b(?:password|username|login|credentials|pin|security code)\b",
            r"\b(?:verify|confirm|update|validate)\s+(?:account|information|"
            r"details)\b",
            r"\b(?:enter|provide|submit)\s+(?:your\s+)?(?:password|details|"
            r"information)\b",
            r"\b(?:click\s+(?:here|below|the\s+link))\b",
        ]

        # Payment request patterns
        self.payment_patterns = [
            # Spanish
            r"\b(?:pagar|pago|transferir|dinero|euros?|dólares?)\b",
            r"\b(?:tarjeta\s+de\s+crédito|número\s+de\s+tarjeta)\b",
            r"\b(?:cuenta\s+bancaria|datos\s+bancarios)\b",
            r"\b(?:multa|deuda|cobro|factura)\b",
            # English
            r"\b(?:pay|payment|transfer|money|dollar|euro)\b",
            r"\b(?:credit\s+card|card\s+number|banking\s+details)\b",
            r"\b(?:bank\s+account|account\s+number)\b",
            r"\b(?:fine|debt|charge|invoice|bill)\b",
        ]

        # Common lexical error patterns (typos that indicate non-native speakers)
        self.error_patterns = [
            # Missing articles
            r"\b(?:go\s+to\s+bank|visit\s+bank|contact\s+bank)\b",
            # Wrong verb forms
            r"\b(?:we\s+was|you\s+was|it\s+were)\b",
            r"\b(?:have\s+went|has\s+went|had\s+went)\b",
            # Common Spanish-English errors
            r"\b(?:assistir|confirme|verifique)\b",  # Spanish verbs in English text
            # Number/article disagreements
            r"\b(?:a\s+informations?|an\s+informations?)\b",
            r"\b(?:this\s+datas?|these\s+data)\b",
        ]

        # Brand entities (financial institutions, tech companies)
        self.brand_entities = {
            "financial": [
                "paypal",
                "amazon",
                "ebay",
                "mercadolibre",
                "santander",
                "bbva",
                "caixabank",
                "ing",
                "scotia",
                "citibank",
                "hsbc",
                "chase",
            ],
            "tech": [
                "microsoft",
                "apple",
                "google",
                "facebook",
                "netflix",
                "spotify",
                "adobe",
                "zoom",
            ],
            "government": ["hacienda", "irs", "social security", "seguridad social"],
        }

        # Threat indicators
        self.threat_patterns = [
            # Spanish
            r"\b(?:cuenta\s+suspendida|acceso\s+bloqueado)\b",
            r"\b(?:actividad\s+sospechosa|intento\s+no\s+autorizado)\b",
            r"\b(?:verificación\s+(?:requerida|necesaria)|confirmar\s+identidad)\b",
            # English
            r"\b(?:account\s+suspended|access\s+blocked)\b",
            r"\b(?:suspicious\s+activity|unauthorized\s+attempt)\b",
            r"\b(?:verification\s+(?:required|needed)|confirm\s+identity)\b",
        ]

    def analyze_text(self, text_content: str) -> Tuple[NLPSignals, List[str]]:
        """
        Analyze text content for phishing indicators.

        Returns:
            Tuple of (NLPSignals, list_of_signal_descriptions)
        """
        if not text_content:
            return NLPSignals(), []

        # Clean and normalize text
        clean_text = self._clean_text(text_content)

        signals = NLPSignals()
        signal_descriptions = []

        # Analyze urgency
        signals.urgency_score = self._analyze_urgency(clean_text)
        if signals.urgency_score > 0.3:
            signal_descriptions.append(
                f"Urgencia detectada (score: {signals.urgency_score:.2f})"
            )

        # Check for credential requests
        signals.credential_request = self._check_credential_request(clean_text)
        if signals.credential_request:
            signal_descriptions.append("Solicitud de credenciales")

        # Check for payment requests
        signals.payment_request = self._check_payment_request(clean_text)
        if signals.payment_request:
            signal_descriptions.append("Solicitud de información financiera")

        # Analyze lexical errors
        signals.lexical_errors = self._count_lexical_errors(clean_text)
        if signals.lexical_errors > 2:
            signal_descriptions.append(f"Errores léxicos ({signals.lexical_errors})")

        # Check language mixing
        signals.language_mixing = self._check_language_mixing(clean_text)
        if signals.language_mixing:
            signal_descriptions.append("Mezcla de idiomas detectada")

        # Extract brand mentions
        signals.brand_mentions = self._extract_brand_mentions(clean_text)
        if signals.brand_mentions:
            signal_descriptions.append(
                f"Marcas mencionadas: {', '.join(signals.brand_mentions[:3])}"
            )

        # Check threat indicators
        signals.threat_indicators = self._extract_threat_indicators(clean_text)
        if signals.threat_indicators:
            signal_descriptions.append("Indicadores de amenaza detectados")

        return signals, signal_descriptions

    def _clean_text(self, text: str) -> str:
        """Clean and normalize text for analysis."""
        # Remove HTML entities and extra whitespace
        text = re.sub(r"&[a-zA-Z0-9#]+;", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip().lower()

    def _analyze_urgency(self, text: str) -> float:
        """Analyze urgency level in text (0-1 score)."""
        urgency_matches = 0
        total_patterns = len(self.urgency_patterns)

        for pattern in self.urgency_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                urgency_matches += 1

        # Additional checks for time-sensitive phrases
        time_sensitive = [
            r"\b(?:hoy|today|now|ahora)\b",
            r"\b\d+\s*(?:hours?|horas?|minutos?|minutes?)\b",
            r"\b(?:expir|caduc|venc)\w*\b",
        ]

        for pattern in time_sensitive:
            if re.search(pattern, text, re.IGNORECASE):
                urgency_matches += 0.5

        return min(urgency_matches / total_patterns, 1.0)

    def _check_credential_request(self, text: str) -> bool:
        """Check if text requests credentials or login information."""
        for pattern in self.credential_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # Additional heuristics
        credential_words = ["password", "contraseña", "login", "verify", "verificar"]
        action_words = ["click", "clic", "enter", "provide", "confirmar"]

        credential_count = sum(1 for word in credential_words if word in text)
        action_count = sum(1 for word in action_words if word in text)

        return credential_count >= 1 and action_count >= 1

    def _check_payment_request(self, text: str) -> bool:
        """Check if text requests payment or financial information."""
        for pattern in self.payment_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # Check for combinations of financial + action words
        financial_words = [
            "bank",
            "card",
            "payment",
            "money",
            "banco",
            "tarjeta",
            "pago",
        ]
        action_words = [
            "update",
            "verify",
            "confirm",
            "provide",
            "actualizar",
            "verificar",
        ]

        financial_count = sum(1 for word in financial_words if word in text)
        action_count = sum(1 for word in action_words if word in text)

        return financial_count >= 1 and action_count >= 1

    def _count_lexical_errors(self, text: str) -> int:
        """Count lexical errors that might indicate non-native speakers."""
        error_count = 0

        for pattern in self.error_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            error_count += len(matches)

        # Check for other indicators
        # Repeated punctuation
        if re.search(r"[!?]{2,}", text):
            error_count += 1

        # All caps words (excluding short ones)
        caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
        if len(caps_words) > 3:
            error_count += 1

        # Inconsistent spacing around punctuation
        if re.search(r"\w[!?.,;:]\w", text):
            error_count += 1

        return error_count

    def _check_language_mixing(self, text: str) -> bool:
        """Check for mixing of Spanish and English."""
        # Simple heuristic: look for language-specific patterns
        spanish_indicators = [
            r"\b(?:el|la|los|las|un|una|de|del|por|para|con|sin|este|esta|que)\b",
            r"\b(?:señor|señora|estimado|gracias|saludos)\b",
        ]

        english_indicators = [
            r"\b(?:the|and|you|your|this|that|with|from|dear|thank|regards)\b",
            r"\b(?:account|service|information|security|update)\b",
        ]

        spanish_matches = sum(
            1
            for pattern in spanish_indicators
            if re.search(pattern, text, re.IGNORECASE)
        )
        english_matches = sum(
            1
            for pattern in english_indicators
            if re.search(pattern, text, re.IGNORECASE)
        )

        # If both languages have significant presence, it's mixing
        return spanish_matches > 2 and english_matches > 2

    def _extract_brand_mentions(self, text: str) -> List[str]:
        """Extract mentions of known brands."""
        mentioned_brands = []

        for category, brands in self.brand_entities.items():
            for brand in brands:
                if brand in text:
                    mentioned_brands.append(brand)

        return list(set(mentioned_brands))  # Remove duplicates

    def _extract_threat_indicators(self, text: str) -> List[str]:
        """Extract threat-related phrases."""
        threat_indicators = []

        for pattern in self.threat_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            threat_indicators.extend(matches)

        # Additional threat phrases
        additional_threats = [
            "cuenta bloqueada",
            "account blocked",
            "suspended",
            "verificación requerida",
            "verification required",
            "actividad sospechosa",
            "suspicious activity",
        ]

        for threat in additional_threats:
            if threat in text:
                threat_indicators.append(threat)

        return list(set(threat_indicators))  # Remove duplicates

    def calculate_nlp_risk_score(self, signals: NLPSignals) -> float:
        """Calculate risk score based on NLP signals (0-100)."""
        score = 0.0

        # Urgency contributes up to 20 points
        score += signals.urgency_score * 20

        # Credential requests are high risk
        if signals.credential_request:
            score += 30.0

        # Payment requests are high risk
        if signals.payment_request:
            score += 25.0

        # Lexical errors indicate potential scam
        score += min(signals.lexical_errors * 3, 15.0)

        # Language mixing is suspicious
        if signals.language_mixing:
            score += 10.0

        # Brand mentions can be spoofing
        if signals.brand_mentions:
            score += min(len(signals.brand_mentions) * 5, 15.0)

        # Threat indicators are serious
        if signals.threat_indicators:
            score += min(len(signals.threat_indicators) * 8, 20.0)

        return min(score, 100.0)
