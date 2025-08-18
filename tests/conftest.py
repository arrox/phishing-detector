import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from src.service import PhishingDetectionService
from src.schema import ClassificationRequest, AccountContext, AttachmentMeta


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_gemini_client():
    """Mock Gemini client for testing."""
    client = Mock()
    client.classify_email = AsyncMock()
    client.create_fallback_response = Mock()
    return client


@pytest.fixture
def detection_service(mock_gemini_client):
    """Create detection service with mocked dependencies."""
    service = PhishingDetectionService("fake-api-key")
    service.gemini_client = mock_gemini_client
    return service


@pytest.fixture
def sample_phishing_request():
    """Sample phishing email request for testing."""
    return ClassificationRequest(
        raw_headers="""From: PayPal <noreply@payp4l-security.com>
To: user@example.com
Subject: Urgent: Account Suspension Notice
Authentication-Results: mx.example.com;
    dmarc=fail (p=reject dis=none) header.from=payp4l-security.com;
    spf=fail smtp.mailfrom=payp4l-security.com;
    dkim=fail header.d=payp4l-security.com
""",
        raw_html="""<html><body>
<h1>PayPal Security Alert</h1>
<p>Your account has been suspended due to suspicious activity.</p>
<p>Click <a href="http://payp4l-security.com/verify">here</a> to verify your account immediately.</p>
<p>You have 24 hours to verify or your account will be permanently closed.</p>
</body></html>""",
        text_body="""PayPal Security Alert

Your account has been suspended due to suspicious activity.

Click here to verify your account immediately: http://payp4l-security.com/verify

You have 24 hours to verify or your account will be permanently closed.

PayPal Security Team""",
        attachments_meta=[],
        account_context=AccountContext(
            user_locale="es-ES", trusted_senders=[], owned_domains=["example.com"]
        ),
    )


@pytest.fixture
def sample_legitimate_request():
    """Sample legitimate email request for testing."""
    return ClassificationRequest(
        raw_headers="""From: PayPal <service@paypal.com>
To: user@example.com
Subject: Your Recent Transaction
Authentication-Results: mx.example.com;
    dmarc=pass header.from=paypal.com;
    spf=pass smtp.mailfrom=paypal.com;
    dkim=pass header.d=paypal.com
""",
        raw_html="""<html><body>
<h1>Transaction Confirmation</h1>
<p>Thank you for your recent transaction.</p>
<p>Transaction ID: TXN123456789</p>
<p>Amount: $25.00</p>
</body></html>""",
        text_body="""Transaction Confirmation

Thank you for your recent transaction.

Transaction ID: TXN123456789
Amount: $25.00

Best regards,
PayPal Team""",
        attachments_meta=[],
        account_context=AccountContext(
            user_locale="es-ES",
            trusted_senders=["service@paypal.com"],
            owned_domains=["example.com"],
        ),
    )


@pytest.fixture
def sample_suspicious_request():
    """Sample suspicious email request for testing."""
    return ClassificationRequest(
        raw_headers="""From: Bank Support <support@bank-security-alert.com>
To: user@example.com
Subject: Action Required: Update Your Banking Information
Authentication-Results: mx.example.com;
    dmarc=none header.from=bank-security-alert.com;
    spf=none smtp.mailfrom=bank-security-alert.com;
    dkim=none header.d=bank-security-alert.com
""",
        raw_html="""<html><body>
<p>Dear valued customer,</p>
<p>We need you to update your banking information for security reasons.</p>
<p>Please visit our secure portal: https://secure-bank-update.com/login</p>
<p>This request expires in 48 hours.</p>
</body></html>""",
        text_body="""Dear valued customer,

We need you to update your banking information for security reasons.

Please visit our secure portal: https://secure-bank-update.com/login

This request expires in 48 hours.

Bank Security Team""",
        attachments_meta=[
            AttachmentMeta(
                filename="bank_form.pdf",
                mime="application/pdf",
                size=45678,
                hash="sha256:abc123def456",
            )
        ],
        account_context=AccountContext(
            user_locale="es-MX", trusted_senders=[], owned_domains=["example.com"]
        ),
    )


@pytest.fixture
def sample_attachment_request():
    """Sample email with suspicious attachments."""
    return ClassificationRequest(
        raw_headers="""From: IT Support <it@company-update.com>
To: user@example.com
Subject: Security Update Required
""",
        raw_html="<html><body><p>Please install the attached security update.</p></body></html>",
        text_body="Please install the attached security update.",
        attachments_meta=[
            AttachmentMeta(
                filename="security_update.exe",
                mime="application/x-executable",
                size=2048576,
                hash="sha256:malicious123",
            ),
            AttachmentMeta(
                filename="instructions.bat",
                mime="application/x-bat",
                size=1024,
                hash="sha256:suspicious456",
            ),
        ],
        account_context=AccountContext(),
    )
