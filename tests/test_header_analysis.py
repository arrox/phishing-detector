import pytest
from src.header_analysis import HeaderAnalyzer
from src.schema import HeaderFindings


class TestHeaderAnalyzer:
    """Test cases for email header analysis."""

    def setUp(self):
        self.analyzer = HeaderAnalyzer()

    def test_spf_dkim_dmarc_pass(self):
        """Test headers with passing authentication."""
        headers = """Authentication-Results: mx.example.com;
    dmarc=pass header.from=paypal.com;
    spf=pass smtp.mailfrom=paypal.com;
    dkim=pass header.d=paypal.com
From: PayPal <service@paypal.com>
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.spf_dkim_dmarc == "ok"
        assert not findings.reply_to_mismatch
        assert not findings.display_name_spoof

    def test_spf_dkim_dmarc_fail(self):
        """Test headers with failing authentication."""
        headers = """Authentication-Results: mx.example.com;
    dmarc=fail (p=reject dis=none) header.from=paypal-security.com;
    spf=fail smtp.mailfrom=paypal-security.com;
    dkim=fail header.d=paypal-security.com
From: PayPal <noreply@paypal-security.com>
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.spf_dkim_dmarc == "fail"

    def test_reply_to_mismatch(self):
        """Test detection of Reply-To mismatch."""
        headers = """From: Bank Support <support@legitimatebank.com>
Reply-To: support@malicioussite.com
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.reply_to_mismatch

    def test_display_name_spoofing(self):
        """Test detection of display name spoofing."""
        headers = """From: PayPal Security <noreply@suspicious-domain.com>
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.display_name_spoof

    def test_punycode_detection(self):
        """Test detection of punycode domains."""
        headers = """From: Apple Support <support@xn--apple-fake.com>
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.punycode_detected

    def test_suspicious_received_chain(self):
        """Test detection of suspicious received chain."""
        headers = """Received: from suspicious.tk ([127.0.0.1])
    by mx.example.com; Mon, 1 Jan 2024 12:00:00 +0000
Received: from localhost ([192.168.1.1])
    by suspicious.tk; Mon, 1 Jan 2024 11:59:00 +0000
From: Support <support@example.com>
To: user@example.com"""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert findings.suspicious_received
        assert len(details["routing_anomalies"]) > 0

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        analyzer = HeaderAnalyzer()

        # High risk findings
        high_risk_findings = HeaderFindings(
            spf_dkim_dmarc="fail",
            reply_to_mismatch=True,
            display_name_spoof=True,
            punycode_detected=True,
            suspicious_received=True,
        )

        high_score = analyzer.calculate_header_risk_score(high_risk_findings)
        assert high_score >= 80

        # Low risk findings
        low_risk_findings = HeaderFindings(
            spf_dkim_dmarc="ok",
            reply_to_mismatch=False,
            display_name_spoof=False,
            punycode_detected=False,
            suspicious_received=False,
        )

        low_score = analyzer.calculate_header_risk_score(low_risk_findings)
        assert low_score < 20

    def test_malformed_headers(self):
        """Test handling of malformed headers."""
        headers = "Invalid header format"

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        # Should not crash and return default findings
        assert isinstance(findings, HeaderFindings)
        assert isinstance(details, dict)

    def test_empty_headers(self):
        """Test handling of empty headers."""
        headers = ""

        analyzer = HeaderAnalyzer()
        findings, details = analyzer.analyze_headers(headers)

        assert isinstance(findings, HeaderFindings)
        assert isinstance(details, dict)

    def test_legitimate_brand_domains(self):
        """Test identification of legitimate brand domains."""
        analyzer = HeaderAnalyzer()

        # Test legitimate domains
        assert analyzer._is_legitimate_brand_domain("paypal", "paypal.com")
        assert analyzer._is_legitimate_brand_domain("amazon", "amazon.es")
        assert analyzer._is_legitimate_brand_domain("google", "gmail.com")

        # Test suspicious domains
        assert not analyzer._is_legitimate_brand_domain("paypal", "payp4l.com")
        assert not analyzer._is_legitimate_brand_domain("amazon", "amazon-security.tk")
        assert not analyzer._is_legitimate_brand_domain("google", "g00gle.com")
