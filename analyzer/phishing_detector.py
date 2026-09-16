import re
from urllib.parse import unquote, urlparse


class PhishingDetector:

    # Baseline trusted domains.
    # This is intentionally small; enterprise deployments
    # should eventually use configurable organization/domain
    # intelligence rather than a hardcoded list.
    TRUSTED_DOMAINS = {
        "google.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
        "paypal.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "ibm.com",
        "tcs.com"
    }

    # Common URL shortening services.
    URL_SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    }

    # TLDs that can deserve additional scrutiny.
    # A TLD alone does NOT mean that a URL is malicious.
    SUSPICIOUS_TLDS = {
        ".zip",
        ".click",
        ".top",
        ".xyz",
        ".work",
        ".download",
        ".country",
        ".gq",
        ".tk",
        ".ml",
        ".cf"
    }

    SUSPICIOUS_KEYWORDS = [
        "verify your account",
        "account suspended",
        "urgent action",
        "click here",
        "reset your password",
        "confirm your account",
        "login immediately",
        "verify your identity",
        "security alert",
        "unusual activity",
        "account will be closed",
        "your account has been locked",
        "update your payment",
        "confirm your payment",
        "payment failed",
        "invoice attached",
        "claim your reward",
        "you have won",
        "limited time",
        "act now"
    ]

    CREDENTIAL_KEYWORDS = [
        "password",
        "username",
        "login",
        "sign in",
        "credentials",
        "otp",
        "one time password",
        "verification code",
        "security code"
    ]

    FINANCIAL_KEYWORDS = [
        "credit card",
        "debit card",
        "bank account",
        "banking",
        "payment",
        "upi",
        "refund",
        "transaction",
        "invoice",
        "wire transfer"
    ]

    URGENCY_KEYWORDS = [
        "urgent",
        "immediately",
        "right now",
        "act now",
        "within 24 hours",
        "final warning",
        "last chance",
        "expires today",
        "suspended",
        "locked"
    ]

    URL_PATTERN = r"https?://[^\s<>\"]+"

    @staticmethod
    def extract_url_features(url):

        parsed = urlparse(url)

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        return {
            "hostname": hostname,
            "uses_https": parsed.scheme.lower() == "https",
            "scheme": parsed.scheme.lower(),
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_count": max(
                hostname.count(".") - 1,
                0
            ),
            "has_ip_address": bool(
                re.match(
                    r"^\d+\.\d+\.\d+\.\d+$",
                    hostname
                )
            ),
            "has_at_symbol": "@" in url,
            "has_punycode": "xn--" in hostname.lower(),
            "has_port": parsed.port is not None,
            "port": parsed.port,
            "has_query": bool(parsed.query),
            "has_fragment": bool(parsed.fragment),
            "query_parameter_count": (
                len(parsed.query.split("&"))
                if parsed.query
                else 0
            ),
            "path_depth": (
                len(
                    [
                        part
                        for part in path.split("/")
                        if part
                    ]
                )
            ),
            "encoded_character_count": (
                len(
                    re.findall(
                        r"%[0-9a-fA-F]{2}",
                        url
                    )
                )
            )
        }

    @staticmethod
    def detect_lookalike_domain(hostname):

        domain = hostname.lower().strip(".")

        for trusted_domain in PhishingDetector.TRUSTED_DOMAINS:

            if domain == trusted_domain:
                continue

            trusted_name = trusted_domain.split(".")[0]

            domain_parts = domain.split(".")

            if len(domain_parts) < 2:
                continue

            domain_name = domain_parts[-2]

            normalized_domain = (
                domain_name
                .replace("0", "o")
                .replace("1", "l")
                .replace("3", "e")
                .replace("5", "s")
                .replace("7", "t")
            )

            # Detect direct character substitution.
            if normalized_domain == trusted_name:
                return {
                    "detected": True,
                    "target": trusted_domain
                }

            # Detect brand impersonation with an added suffix/prefix.
            normalized_compact = normalized_domain.replace(
                "-", ""
            )

            trusted_compact = trusted_name.replace(
                "-", ""
            )

            if (
                trusted_compact in normalized_compact
                and normalized_compact != trusted_compact
            ):
                return {
                    "detected": True,
                    "target": trusted_domain
                }

        return {
            "detected": False,
            "target": None
        }

    @staticmethod
    def detect_trusted_brand_in_subdomain(hostname):

        hostname = hostname.lower()

        for trusted_domain in PhishingDetector.TRUSTED_DOMAINS:

            brand = trusted_domain.split(".")[0]

            if (
                brand in hostname
                and not hostname.endswith(trusted_domain)
            ):
                return {
                    "detected": True,
                    "brand": brand,
                    "trusted_domain": trusted_domain
                }

        return {
            "detected": False,
            "brand": None,
            "trusted_domain": None
        }

    @staticmethod
    def detect_suspicious_tld(hostname):

        hostname = hostname.lower()

        return any(
            hostname.endswith(tld)
            for tld in PhishingDetector.SUSPICIOUS_TLDS
        )

    @staticmethod
    def detect_url_shortener(hostname):

        hostname = hostname.lower().strip(".")

        return hostname in PhishingDetector.URL_SHORTENERS

    @staticmethod
    def detect_obfuscation(url):

        decoded_url = unquote(url)

        indicators = []

        if decoded_url != url:
            indicators.append(
                "URL contains percent-encoded characters"
            )

        if re.search(r"%25[0-9a-fA-F]{2}", url):
            indicators.append(
                "Double URL encoding detected"
            )

        if re.search(
            r"0x[0-9a-fA-F]+",
            url,
            re.IGNORECASE
        ):
            indicators.append(
                "Hexadecimal URL representation"
            )

        return indicators

    @staticmethod
    def detect_message_indicators(message):

        message_lower = message.lower()

        credential_requests = [
            keyword
            for keyword in PhishingDetector.CREDENTIAL_KEYWORDS
            if keyword in message_lower
        ]

        financial_requests = [
            keyword
            for keyword in PhishingDetector.FINANCIAL_KEYWORDS
            if keyword in message_lower
        ]

        urgency_indicators = [
            keyword
            for keyword in PhishingDetector.URGENCY_KEYWORDS
            if keyword in message_lower
        ]

        return {
            "credential_requests": credential_requests,
            "financial_requests": financial_requests,
            "urgency_indicators": urgency_indicators
        }

    def analyze(self, message):

        if not isinstance(message, str):
            raise TypeError("message must be a string")

        message_lower = message.lower()

        matched_keywords = [
            keyword
            for keyword in self.SUSPICIOUS_KEYWORDS
            if keyword in message_lower
        ]

        message_indicators = self.detect_message_indicators(
            message
        )

        urls = re.findall(
            self.URL_PATTERN,
            message,
            re.IGNORECASE
        )

        suspicious_urls = []

        for url in urls:

            features = self.extract_url_features(url)

            hostname = features["hostname"]

            reasons = []

            if features["has_ip_address"]:
                reasons.append(
                    "IP address used instead of domain"
                )

            if features["has_at_symbol"]:
                reasons.append(
                    "URL contains @ symbol"
                )

            if features["subdomain_count"] >= 3:
                reasons.append(
                    "Excessive subdomains"
                )

            if features["has_punycode"]:
                reasons.append(
                    "Punycode domain"
                )

            if features["url_length"] > 100:
                reasons.append(
                    "Unusually long URL"
                )

            if features["has_port"]:
                if features["port"] not in {
                    80,
                    443
                }:
                    reasons.append(
                        "Non-standard web port"
                    )

            if features["query_parameter_count"] >= 5:
                reasons.append(
                    "Large number of URL parameters"
                )

            if features["encoded_character_count"] >= 3:
                reasons.append(
                    "Heavy URL encoding"
                )

            if self.detect_url_shortener(hostname):
                reasons.append(
                    "URL shortening service"
                )

            if self.detect_suspicious_tld(hostname):
                reasons.append(
                    "Potentially high-risk TLD"
                )

            lookalike = self.detect_lookalike_domain(
                hostname
            )

            if lookalike["detected"]:
                reasons.append(
                    "Possible lookalike domain for "
                    f"{lookalike['target']}"
                )

            brand_impersonation = (
                self.detect_trusted_brand_in_subdomain(
                    hostname
                )
            )

            if brand_impersonation["detected"]:
                reasons.append(
                    "Trusted brand appears in "
                    "suspicious hostname"
                )

            reasons.extend(
                self.detect_obfuscation(url)
            )

            if reasons:
                suspicious_urls.append({
                    "url": url,
                    "hostname": hostname,
                    "reasons": reasons,
                    "features": features
                })

        risk_score = 0

        # Content signals.
        risk_score += min(
            len(matched_keywords) * 10,
            30
        )

        if message_indicators[
            "credential_requests"
        ]:
            risk_score += 10

        if message_indicators[
            "financial_requests"
        ]:
            risk_score += 10

        if message_indicators[
            "urgency_indicators"
        ]:
            risk_score += 10

        # URL signals.
        for suspicious_url in suspicious_urls:

            risk_score += 20

            reasons = suspicious_url["reasons"]

            if any(
                "lookalike" in reason.lower()
                for reason in reasons
            ):
                risk_score += 20

            if any(
                "punycode" in reason.lower()
                for reason in reasons
            ):
                risk_score += 15

        risk_score = min(
            risk_score,
            100
        )

        if risk_score >= 60:
            risk = "CRITICAL"

        elif risk_score >= 40:
            risk = "HIGH"

        elif risk_score >= 20:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        return {
            "is_phishing": risk in {
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            },
            "risk": risk,
            "risk_score": risk_score,
            "matched_keywords": matched_keywords,
            "message_indicators": message_indicators,
            "urls_found": urls,
            "suspicious_urls": suspicious_urls
        }