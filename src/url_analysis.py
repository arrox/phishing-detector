import re
import asyncio
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass
import logging
import httpx
import dns.resolver
import whois
import Levenshtein
from bs4 import BeautifulSoup
import publicsuffix2

from src.schema import URLFinding

logger = logging.getLogger(__name__)


@dataclass
class URLMetadata:
    url: str
    domain: str
    https: bool
    redirections: int
    domain_similarity: Optional[float]
    whois_age_days: Optional[int]
    blacklist_hit: bool
    final_url: Optional[str] = None
    response_code: Optional[int] = None
    title: Optional[str] = None


class URLAnalyzer:
    """Analyzes URLs for phishing indicators with parallel processing."""

    def __init__(self):
        self.timeout = 0.3  # 300ms timeout per check
        self.max_redirects = 3

        # Common legitimate domains for similarity checking
        self.legitimate_brands = [
            "paypal.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "google.com",
            "facebook.com",
            "netflix.com",
            "ebay.com",
            "bancosantander.es",
            "bbva.es",
            "caixabank.es",
            "bancochile.cl",
            "santander.com",
            "scotiabank.com",
        ]

        # Suspicious URL patterns
        self.suspicious_patterns = [
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP addresses
            r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(tk|ml|ga|cf)",  # Suspicious TLD patterns
            r"(secure|account|verify|update|login).*[0-9]+",  # Generic + numbers
            r"[a-z]+\d+[a-z]*\.(com|net|org)",  # Mixed letters/numbers
        ]

        # URL shorteners
        self.url_shorteners = {
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "short.link",
            "ow.ly",
            "buff.ly",
            "s.id",
            "rb.gy",
        }

        # Initialize DNS resolver
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 0.2
        self.dns_resolver.lifetime = 0.3

    async def analyze_urls(
        self, html_content: str, text_content: str
    ) -> Tuple[List[URLFinding], List[Dict[str, Any]]]:
        """
        Extract and analyze all URLs from content.

        Returns:
            Tuple of (url_findings, url_metadata_list)
        """
        urls = self._extract_urls(html_content, text_content)
        if not urls:
            return [], []

        # Limit URLs to avoid timeouts
        urls = urls[:10]  # Analyze max 10 URLs

        # Analyze URLs in parallel
        tasks = [self._analyze_single_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        url_findings = []
        url_metadata = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"URL analysis failed for {urls[i]}: {result}")
                # Create minimal metadata for failed analysis
                url_metadata.append(
                    {
                        "url": urls[i],
                        "domain": self._extract_domain(urls[i]),
                        "analysis_failed": True,
                    }
                )
                continue

            finding, metadata = result
            if finding:
                url_findings.append(finding)
            url_metadata.append(metadata.to_dict())

        return url_findings, url_metadata

    def _extract_urls(self, html_content: str, text_content: str) -> List[str]:
        """Extract URLs from HTML and text content."""
        urls = set()

        # Extract from HTML
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            for tag in soup.find_all(["a", "img", "form"]):
                for attr in ["href", "src", "action"]:
                    url = tag.get(attr)
                    if url and url.startswith(("http://", "https://")):
                        urls.add(url)

        # Extract from text using regex
        url_pattern = re.compile(
            r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?",
            re.IGNORECASE,
        )

        text_urls = url_pattern.findall(text_content)
        urls.update(text_urls)

        return list(urls)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""

    async def _analyze_single_url(
        self, url: str
    ) -> Tuple[Optional[URLFinding], URLMetadata]:
        """Analyze a single URL for phishing indicators."""
        start_time = time.time()

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            metadata = URLMetadata(
                url=url,
                domain=domain,
                https=parsed.scheme == "https",
                redirections=0,
                domain_similarity=None,
                whois_age_days=None,
                blacklist_hit=False,
            )

            # Quick pattern checks (no network calls)
            risk_reasons = []
            risk_level = "low"

            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    risk_reasons.append(f"Suspicious pattern detected")
                    risk_level = "medium"
                    break

            # Check if it's an IP address
            if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", url):
                risk_reasons.append("Uses IP address instead of domain")
                risk_level = "high"

            # Check for URL shorteners
            if domain in self.url_shorteners:
                risk_reasons.append("URL shortener detected")
                risk_level = "medium"

            # Check HTTPS
            if not metadata.https:
                risk_reasons.append("No HTTPS encryption")
                risk_level = "medium"

            # Check domain similarity (network-free)
            similarity = self._check_domain_similarity(domain)
            if similarity and similarity > 0.8:
                risk_reasons.append("Similar to legitimate domain")
                metadata.domain_similarity = similarity
                risk_level = "high"

            # Network-based checks with timeout
            remaining_time = self.timeout - (time.time() - start_time)
            if remaining_time > 0.1:  # Only if we have time left
                await self._network_checks(url, metadata, risk_reasons, remaining_time)

            # Create finding if risks detected
            finding = None
            if risk_reasons:
                finding = URLFinding(
                    url=url,
                    reason="; ".join(risk_reasons[:2]),  # Max 2 reasons
                    risk_level=risk_level,
                )

            return finding, metadata

        except Exception as e:
            logger.error(f"URL analysis error for {url}: {e}")
            return None, URLMetadata(
                url=url,
                domain=self._extract_domain(url),
                https=False,
                redirections=0,
                domain_similarity=None,
                whois_age_days=None,
                blacklist_hit=False,
            )

    def _check_domain_similarity(self, domain: str) -> Optional[float]:
        """Check similarity to legitimate domains using Levenshtein distance."""
        if not domain:
            return None

        # Extract the main domain part for comparison
        try:
            psl = publicsuffix2.PublicSuffixList()
            main_domain = psl.get_public_suffix(domain)
        except Exception:
            main_domain = domain

        max_similarity = 0.0

        for legit_domain in self.legitimate_brands:
            # Compare main domain parts
            try:
                legit_main = publicsuffix2.PublicSuffixList().get_public_suffix(
                    legit_domain
                )
            except Exception:
                legit_main = legit_domain

            # Calculate similarity
            similarity = 1.0 - (
                Levenshtein.distance(main_domain, legit_main)
                / max(len(main_domain), len(legit_main))
            )

            if similarity > max_similarity:
                max_similarity = similarity

        return max_similarity if max_similarity > 0.7 else None

    async def _network_checks(
        self, url: str, metadata: URLMetadata, risk_reasons: List[str], timeout: float
    ) -> None:
        """Perform network-based checks with timeout."""
        tasks = []

        # HTTP HEAD request for redirects and status
        tasks.append(self._check_redirects(url, timeout / 3))

        # DNS checks
        tasks.append(self._dns_check(metadata.domain, timeout / 3))

        # WHOIS check
        tasks.append(self._whois_check(metadata.domain, timeout / 3))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=timeout
            )

            # Process redirect results
            if not isinstance(results[0], Exception):
                redirect_info = results[0]
                metadata.redirections = redirect_info.get("redirects", 0)
                metadata.response_code = redirect_info.get("status_code")
                metadata.final_url = redirect_info.get("final_url")

                if metadata.redirections > 2:
                    risk_reasons.append("Multiple redirects detected")

            # Process DNS results
            if not isinstance(results[1], Exception) and results[1]:
                dns_age = results[1]
                if dns_age < 30:  # Domain less than 30 days old
                    risk_reasons.append("Recently created domain")

            # Process WHOIS results
            if not isinstance(results[2], Exception) and results[2]:
                whois_age = results[2]
                metadata.whois_age_days = whois_age
                if whois_age < 30:
                    risk_reasons.append("Domain registered recently")

        except asyncio.TimeoutError:
            logger.warning(f"Network checks timeout for {url}")

    async def _check_redirects(self, url: str, timeout: float) -> Dict[str, Any]:
        """Check URL redirects with HEAD request."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.head(url, follow_redirects=True)

                redirect_count = len(response.history)
                final_url = str(response.url) if response.url != url else None

                return {
                    "redirects": redirect_count,
                    "status_code": response.status_code,
                    "final_url": final_url,
                }
        except Exception:
            return {"redirects": 0, "status_code": None, "final_url": None}

    async def _dns_check(self, domain: str, timeout: float) -> Optional[int]:
        """Check domain age via DNS (simplified)."""
        try:
            # This is a simplified check - in production you'd use
            # specialized DNS history services
            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "A")
                ),
                timeout=timeout,
            )
            # If DNS resolves, assume domain is established (>30 days)
            return 100  # Default to established
        except Exception:
            return None

    async def _whois_check(self, domain: str, timeout: float) -> Optional[int]:
        """Check domain registration age via WHOIS."""
        try:
            whois_info = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: whois.whois(domain)
                ),
                timeout=timeout,
            )

            if whois_info and whois_info.creation_date:
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                from datetime import datetime

                age_days = (datetime.now() - creation_date).days
                return age_days

        except Exception:
            pass

        return None

    def calculate_url_risk_score(self, findings: List[URLFinding]) -> float:
        """Calculate risk score based on URL findings (0-100)."""
        if not findings:
            return 0.0

        score = 0.0

        for finding in findings:
            if finding.risk_level == "high":
                score += 30.0
            elif finding.risk_level == "medium":
                score += 15.0
            else:
                score += 5.0

        # Bonus for multiple suspicious URLs
        if len(findings) > 1:
            score += min(len(findings) * 5, 20)

        return min(score, 100.0)


# Extension to URLMetadata for JSON serialization
class URLMetadataDict(URLMetadata):
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "https": self.https,
            "redirections": self.redirections,
            "domain_similarity": self.domain_similarity,
            "whois_age_days": self.whois_age_days,
            "blacklist_hit": self.blacklist_hit,
            "final_url": self.final_url,
            "response_code": self.response_code,
            "title": self.title,
        }


# Monkey patch for to_dict method
URLMetadata.to_dict = URLMetadataDict.to_dict
