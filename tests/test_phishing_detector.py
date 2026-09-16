from analyzer.phishing_detector import PhishingDetector


def test_phishing_keywords():
    detector = PhishingDetector()

    result = detector.analyze(
        "Urgent action required. Verify your account "
        "and login immediately."
    )

    assert result["is_phishing"] is True
    assert result["risk"] in {"HIGH", "CRITICAL"}
    assert len(result["matched_keywords"]) >= 2


def test_suspicious_ip_url():
    detector = PhishingDetector()

    result = detector.analyze(
        "Please login here: http://192.168.1.100/login"
    )

    assert result["is_phishing"] is True
    assert len(result["suspicious_urls"]) == 1
    assert (
        "IP address used instead of domain"
        in result["suspicious_urls"][0]["reasons"]
    )


def test_punycode_url():
    detector = PhishingDetector()

    result = detector.analyze(
        "Verify your account: "
        "https://xn--example-9za.com/login"
    )

    assert result["is_phishing"] is True
    assert (
        "Punycode domain"
        in result["suspicious_urls"][0]["reasons"]
    )


def test_lookalike_domain():
    detector = PhishingDetector()

    result = detector.analyze(
        "Login: https://paypa1-security.com/login"
    )

    assert result["is_phishing"] is True
    assert any(
        "lookalike domain" in reason.lower()
        for reason in result["suspicious_urls"][0]["reasons"]
    )


def test_url_shortener():
    detector = PhishingDetector()

    result = detector.analyze(
        "Click here: https://bit.ly/abc123"
    )

    assert result["is_phishing"] is True
    assert any(
        "shortening service" in reason.lower()
        for reason in result["suspicious_urls"][0]["reasons"]
    )


def test_excessive_subdomains():
    detector = PhishingDetector()

    result = detector.analyze(
        "Login: "
        "https://login.security.account.verify.example.com/auth"
    )

    assert result["is_phishing"] is True
    assert any(
        "subdomains" in reason.lower()
        for reason in result["suspicious_urls"][0]["reasons"]
    )


def test_non_standard_port():
    detector = PhishingDetector()

    result = detector.analyze(
        "Login: https://example.com:8080/login"
    )

    assert result["is_phishing"] is True
    assert any(
        "non-standard web port" in reason.lower()
        for reason in result["suspicious_urls"][0]["reasons"]
    )


def test_credential_request():
    detector = PhishingDetector()

    result = detector.analyze(
        "Your account requires verification. "
        "Enter your username and password immediately."
    )

    assert result["is_phishing"] is True
    assert result["message_indicators"]["credential_requests"]


def test_financial_request():
    detector = PhishingDetector()

    result = detector.analyze(
        "Your payment failed. Please update your credit card."
    )

    assert result["is_phishing"] is True
    assert result["message_indicators"]["financial_requests"]


def test_urgency_detection():
    detector = PhishingDetector()

    result = detector.analyze(
        "Final warning. Act now or your account will be locked."
    )

    assert result["is_phishing"] is True
    assert result["message_indicators"]["urgency_indicators"]


def test_encoded_url():
    detector = PhishingDetector()

    result = detector.analyze(
        "Visit https://example.com/%6cogin/%70assword"
    )

    assert result["is_phishing"] is True
    assert any(
        "encoded" in reason.lower()
        for reason in result["suspicious_urls"][0]["reasons"]
    )


def test_normal_message():
    detector = PhishingDetector()

    result = detector.analyze(
        "Hello, the meeting is scheduled "
        "for tomorrow at 10 AM."
    )

    assert result["is_phishing"] is False
    assert result["risk"] == "LOW"
    assert result["risk_score"] == 0


def test_normal_https_url():
    detector = PhishingDetector()

    result = detector.analyze(
        "Our documentation is available at "
        "https://github.com/project/docs"
    )

    assert result["is_phishing"] is False
    assert result["risk"] == "LOW"


def test_invalid_message_type():
    detector = PhishingDetector()

    try:
        detector.analyze(None)
        assert False
    except TypeError:
        assert True

def test_phishing_intelligence_output():

    detector = PhishingDetector()

    result = detector.analyze(
        "Urgent! Visit https://evil.example.com/login"
    )

    assert "intelligence" in result
    assert "https://evil.example.com/login" in result["intelligence"]["urls"]
    assert "evil.example.com" in result["intelligence"]["domains"] 