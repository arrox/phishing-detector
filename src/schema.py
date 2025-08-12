from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, validator
import re


class AttachmentMeta(BaseModel):
    filename: str
    mime: str
    size: int
    hash: str


class AccountContext(BaseModel):
    user_locale: str = "es-ES"
    trusted_senders: List[str] = Field(default_factory=list)
    owned_domains: List[str] = Field(default_factory=list)


class ClassificationRequest(BaseModel):
    raw_headers: str
    raw_html: str
    text_body: str
    attachments_meta: List[AttachmentMeta] = Field(default_factory=list)
    account_context: AccountContext = Field(default_factory=AccountContext)


class HeaderFindings(BaseModel):
    spf_dkim_dmarc: Literal["ok", "mismatch", "fail"] = "ok"
    reply_to_mismatch: bool = False
    display_name_spoof: bool = False
    punycode_detected: bool = False
    suspicious_received: bool = False


class URLFinding(BaseModel):
    url: str
    reason: str
    risk_level: Literal["low", "medium", "high"] = "low"


class Evidence(BaseModel):
    header_findings: HeaderFindings
    url_findings: List[URLFinding] = Field(default_factory=list)
    nlp_signals: List[str] = Field(default_factory=list)


class ClassificationResponse(BaseModel):
    classification: Literal["phishing", "sospechoso", "seguro"]
    risk_score: int = Field(ge=0, le=100)
    top_reasons: List[str] = Field(max_items=3)
    non_technical_summary: str = Field(max_length=200)
    recommended_actions: List[str] = Field(max_items=3)
    evidence: Evidence
    latency_ms: int

    @validator('non_technical_summary')
    def validate_summary_length(cls, v):
        words = len(v.split())
        if words > 60:
            raise ValueError('Summary must be 60 words or less')
        return v


class HeuristicFeatures(BaseModel):
    header_score: float = 0.0
    url_score: float = 0.0
    nlp_score: float = 0.0
    attachment_score: float = 0.0
    total_score: float = 0.0
    signals: Dict[str, Any] = Field(default_factory=dict)


class GeminiPromptData(BaseModel):
    headers_raw: str
    text_body: str
    html_snippets: List[str]
    attachments_meta: List[AttachmentMeta]
    url_metadata: List[Dict[str, Any]]
    heuristic_summary: str
    account_context: AccountContext
    latency_budget_ms: int = 1200