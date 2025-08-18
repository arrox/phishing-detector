import email
import email.utils
import logging
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from src.schema import HeaderFindings

logger = logging.getLogger(__name__)


@dataclass
class SPFResult:
    status: str  # "pass", "fail", "softfail", "neutral", "none"
    mechanism: Optional[str] = None


@dataclass
class DKIMResult:
    status: str  # "pass", "fail", "none"
    domain: Optional[str] = None


@dataclass
class DMARCResult:
    status: str  # "pass", "fail", "none"
    policy: Optional[str] = None


class HeaderAnalyzer:
    """Analyzes email headers for phishing indicators."""

    def __init__(self):
        self.suspicious_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".click",
            ".download",
            ".bid",
            ".loan",
            ".racing",
            ".accountant",
            ".science",
            ".work",
        }

        # Common brand spoofing patterns
        self.brand_patterns = [
            r"paypal|payp4l|payp al",
            r"amazon|amazom|amazon",
            r"microsoft|microsft|micr0soft",
            r"apple|appl3|app1e",
            r"google|g00gle|googIe",
            r"facebook|faceb00k|f4cebook",
            r"netflix|netfl1x|n3tflix",
            r"banco|bank|santander|bbva|scotia",
        ]

    def analyze_headers(self, raw_headers: str) -> Tuple[HeaderFindings, Dict]:
        """
        Analyze email headers for security signals.

        Returns:
            Tuple of (HeaderFindings, analysis_details)
        """
        try:
            msg = email.message_from_string(raw_headers)

            findings = HeaderFindings()
            details = {
                "received_chain": [],
                "authentication_results": {},
                "routing_anomalies": [],
            }

            # Parse authentication results
            spf_result = self._parse_spf(msg)
            dkim_result = self._parse_dkim(msg)
            dmarc_result = self._parse_dmarc(msg)

            # Determine overall authentication status
            findings.spf_dkim_dmarc = self._get_auth_status(
                spf_result, dkim_result, dmarc_result
            )
            details["authentication_results"] = {
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result,
            }

            # Check for reply-to mismatch
            findings.reply_to_mismatch = self._check_reply_to_mismatch(msg)

            # Check for display name spoofing
            findings.display_name_spoof = self._check_display_name_spoof(msg)

            # Check for punycode in domains
            findings.punycode_detected = self._check_punycode(msg)

            # Analyze received chain
            findings.suspicious_received = self._analyze_received_chain(msg, details)

            return findings, details

        except Exception as e:
            logger.error(f"Header analysis error: {e}")
            return HeaderFindings(), {}

    def _parse_spf(self, msg: email.message.Message) -> SPFResult:
        """Parse SPF authentication results."""
        auth_results = msg.get("Authentication-Results", "").lower()
        received_spf = msg.get("Received-SPF", "").lower()

        if "spf=pass" in auth_results:
            return SPFResult("pass")
        elif "spf=fail" in auth_results:
            return SPFResult("fail")
        elif "spf=softfail" in auth_results:
            return SPFResult("softfail")
        elif "spf=neutral" in auth_results:
            return SPFResult("neutral")
        elif received_spf:
            if "pass" in received_spf:
                return SPFResult("pass")
            elif "fail" in received_spf:
                return SPFResult("fail")

        return SPFResult("none")

    def _parse_dkim(self, msg: email.message.Message) -> DKIMResult:
        """Parse DKIM authentication results."""
        auth_results = msg.get("Authentication-Results", "").lower()
        dkim_signature = msg.get("DKIM-Signature", "")

        if "dkim=pass" in auth_results:
            # Extract domain from DKIM signature if available
            domain_match = re.search(r"d=([^;]+)", dkim_signature)
            domain = domain_match.group(1) if domain_match else None
            return DKIMResult("pass", domain)
        elif "dkim=fail" in auth_results:
            return DKIMResult("fail")
        elif dkim_signature:
            return DKIMResult("neutral")

        return DKIMResult("none")

    def _parse_dmarc(self, msg: email.message.Message) -> DMARCResult:
        """Parse DMARC authentication results."""
        auth_results = msg.get("Authentication-Results", "").lower()

        if "dmarc=pass" in auth_results:
            return DMARCResult("pass")
        elif "dmarc=fail" in auth_results:
            # Extract policy if available
            policy_match = re.search(r"dmarc=fail[^;]*policy\.([^;]+)", auth_results)
            policy = policy_match.group(1) if policy_match else None
            return DMARCResult("fail", policy)

        return DMARCResult("none")

    def _get_auth_status(
        self, spf: SPFResult, dkim: DKIMResult, dmarc: DMARCResult
    ) -> str:
        """Determine overall authentication status."""
        if dmarc.status == "fail":
            return "fail"
        elif spf.status == "fail" and dkim.status == "fail":
            return "fail"
        elif spf.status in ["pass", "neutral"] and dkim.status == "pass":
            return "ok"
        elif spf.status == "fail" or dkim.status == "fail":
            return "mismatch"
        else:
            return "ok"

    def _check_reply_to_mismatch(self, msg: email.message.Message) -> bool:
        """Check if Reply-To differs significantly from From address."""
        from_addr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")

        if not reply_to:
            return False

        try:
            from_email = email.utils.parseaddr(from_addr)[1].lower()
            reply_email = email.utils.parseaddr(reply_to)[1].lower()

            if from_email and reply_email and from_email != reply_email:
                # Check if domains are different
                from_domain = from_email.split("@")[-1] if "@" in from_email else ""
                reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""

                return from_domain != reply_domain
        except Exception:
            return False

        return False

    def _check_display_name_spoof(self, msg: email.message.Message) -> bool:
        """Check for display name spoofing (trusted brand in display name)."""
        from_field = msg.get("From", "")

        if not from_field:
            return False

        try:
            display_name, email_addr = email.utils.parseaddr(from_field)

            if not display_name:
                return False

            display_name_lower = display_name.lower()

            # Check if display name contains brand patterns
            for pattern in self.brand_patterns:
                if re.search(pattern, display_name_lower):
                    # Check if email domain matches the brand
                    if email_addr:
                        domain = email_addr.split("@")[-1].lower()
                        # This is a simplified check - in production, you'd have
                        # a whitelist of legitimate domains for each brand
                        if not self._is_legitimate_brand_domain(pattern, domain):
                            return True

            return False

        except Exception:
            return False

    def _is_legitimate_brand_domain(self, brand_pattern: str, domain: str) -> bool:
        """Check if domain is legitimate for the brand (simplified)."""
        # This is a simplified implementation
        # In production, maintain a whitelist of legitimate domains
        brand_domains = {
            "paypal": ["paypal.com", "paypal.es", "paypal.mx"],
            "amazon": ["amazon.com", "amazon.es", "amazon.mx"],
            "microsoft": ["microsoft.com", "outlook.com", "hotmail.com"],
            "google": ["google.com", "gmail.com", "googlemail.com"],
            "apple": ["apple.com", "icloud.com"],
        }

        for brand, domains in brand_domains.items():
            if brand in brand_pattern:
                return any(domain.endswith(legit_domain) for legit_domain in domains)

        return False

    def _check_punycode(self, msg: email.message.Message) -> bool:
        """Check for punycode (IDN homograph attacks) in email addresses."""
        from_addr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")

        for addr_field in [from_addr, reply_to]:
            if addr_field and "xn--" in addr_field.lower():
                return True

        return False

    def _analyze_received_chain(
        self, msg: email.message.Message, details: Dict
    ) -> bool:
        """Analyze the Received header chain for anomalies."""
        received_headers = msg.get_all("Received", [])

        if not received_headers:
            return False

        details["received_chain"] = received_headers
        suspicious_indicators = 0

        for received in received_headers:
            received_lower = received.lower()

            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if tld in received_lower:
                    suspicious_indicators += 1
                    details["routing_anomalies"].append(f"Suspicious TLD: {tld}")

            # Check for localhost/private IPs in unexpected places
            if re.search(
                r"\b(?:127\.|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)", received
            ):
                suspicious_indicators += 1
                details["routing_anomalies"].append("Private IP in routing")

            # Check for missing or malformed hop information
            if not re.search(r"by .+ for .+", received_lower):
                suspicious_indicators += 1
                details["routing_anomalies"].append("Malformed received header")

        return suspicious_indicators >= 2

    def calculate_header_risk_score(self, findings: HeaderFindings) -> float:
        """Calculate risk score based on header findings (0-100)."""
        score = 0.0

        # Authentication failures
        if findings.spf_dkim_dmarc == "fail":
            score += 35.0
        elif findings.spf_dkim_dmarc == "mismatch":
            score += 20.0

        # Reply-to mismatch
        if findings.reply_to_mismatch:
            score += 15.0

        # Display name spoofing
        if findings.display_name_spoof:
            score += 25.0

        # Punycode attacks
        if findings.punycode_detected:
            score += 20.0

        # Suspicious routing
        if findings.suspicious_received:
            score += 10.0

        return min(score, 100.0)
