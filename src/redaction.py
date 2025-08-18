import hashlib
import logging
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)


class PIIRedactor:
    """Redacts personally identifiable information for privacy compliance."""

    def __init__(self):
        self.email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE
        )
        self.phone_pattern = re.compile(
            r"\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b"
        )
        self.account_pattern = re.compile(
            r"\b(?:account|cuenta|número|number)[\s#:]*([0-9]{6,})\b", re.IGNORECASE
        )
        self.credit_card_pattern = re.compile(
            r"\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
        )

    def redact_email(self, email: str) -> str:
        """Mask email local part: user@domain.com -> u***@domain.com"""
        if "@" not in email:
            return email

        local, domain = email.split("@", 1)
        if len(local) <= 2:
            return f"{'*' * len(local)}@{domain}"
        return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"

    def hash_sensitive_data(self, data: str) -> str:
        """Generate SHA-256 hash for logging sensitive data."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def redact_text(
        self, text: str, preserve_context: bool = True
    ) -> Tuple[str, List[str]]:
        """
        Redact PII from text while preserving context for analysis.

        Returns:
            Tuple of (redacted_text, list_of_redaction_hashes)
        """
        redacted = text
        redaction_hashes = []

        # Redact emails
        for match in self.email_pattern.finditer(text):
            email = match.group()
            if preserve_context:
                redacted_email = self.redact_email(email)
            else:
                redacted_email = "[EMAIL_REDACTED]"
            redacted = redacted.replace(email, redacted_email)
            redaction_hashes.append(f"email:{self.hash_sensitive_data(email)}")

        # Redact phone numbers
        for match in self.phone_pattern.finditer(redacted):
            phone = match.group()
            if preserve_context:
                masked_phone = phone[:3] + "*" * (len(phone) - 6) + phone[-3:]
            else:
                masked_phone = "[PHONE_REDACTED]"
            redacted = redacted.replace(phone, masked_phone)
            redaction_hashes.append(f"phone:{self.hash_sensitive_data(phone)}")

        # Redact account numbers
        for match in self.account_pattern.finditer(redacted):
            full_match = match.group()
            account_num = match.group(1)
            if preserve_context and len(account_num) > 4:
                masked_account = (
                    account_num[:2] + "*" * (len(account_num) - 4) + account_num[-2:]
                )
                redacted = redacted.replace(account_num, masked_account)
            else:
                redacted = redacted.replace(full_match, "[ACCOUNT_REDACTED]")
            redaction_hashes.append(f"account:{self.hash_sensitive_data(account_num)}")

        # Redact credit card numbers
        for match in self.credit_card_pattern.finditer(redacted):
            cc = match.group()
            cleaned_cc = re.sub(r"[-\s]", "", cc)
            if len(cleaned_cc) == 16:  # Valid CC length
                if preserve_context:
                    masked_cc = cleaned_cc[:4] + "*" * 8 + cleaned_cc[-4:]
                else:
                    masked_cc = "[CC_REDACTED]"
                redacted = redacted.replace(cc, masked_cc)
                redaction_hashes.append(f"cc:{self.hash_sensitive_data(cleaned_cc)}")

        return redacted, redaction_hashes

    def redact_headers(self, headers: str) -> str:
        """Redact headers while preserving routing information."""
        redacted_headers, _ = self.redact_text(headers, preserve_context=True)

        # Additional header-specific redactions
        lines = redacted_headers.split("\n")
        processed_lines = []

        for line in lines:
            # Preserve structure but redact sensitive header values
            if line.lower().startswith(
                ("x-forwarded-for:", "x-real-ip:", "x-client-ip:")
            ):
                header_name = line.split(":", 1)[0]
                processed_lines.append(f"{header_name}: [IP_REDACTED]")
            else:
                processed_lines.append(line)

        return "\n".join(processed_lines)

    def extract_safe_snippets(self, text: str, max_length: int = 500) -> List[str]:
        """Extract safe text snippets for LLM analysis."""
        redacted_text, _ = self.redact_text(text, preserve_context=False)

        # Split into sentences and select relevant ones
        sentences = re.split(r"[.!?]+", redacted_text)

        # Prioritize sentences with security-relevant keywords
        security_keywords = [
            "urgent",
            "urgente",
            "immediate",
            "inmediato",
            "verify",
            "verificar",
            "account",
            "cuenta",
            "password",
            "contraseña",
            "click",
            "clic",
            "suspended",
            "suspendida",
            "expired",
            "expirada",
            "update",
            "actualizar",
        ]

        relevant_sentences = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 20:  # Skip very short sentences
                continue

            # Check for security keywords
            if any(keyword in sentence.lower() for keyword in security_keywords):
                relevant_sentences.append(sentence)
            elif len(relevant_sentences) < 3:  # Keep some context
                relevant_sentences.append(sentence)

        # Combine sentences up to max_length
        snippets = []
        current_snippet = ""

        for sentence in relevant_sentences:
            if len(current_snippet + sentence) < max_length:
                current_snippet += sentence + ". "
            else:
                if current_snippet:
                    snippets.append(current_snippet.strip())
                current_snippet = sentence + ". "

        if current_snippet:
            snippets.append(current_snippet.strip())

        return snippets[:3]  # Return max 3 snippets
