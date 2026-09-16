from analyzer.phishing_intel import PhishingIntelligence


def test_extract_indicators():

    intelligence = PhishingIntelligence()

    result = intelligence.extract_indicators(
        "Visit https://example.com/login "
        "or https://evil.example.org/verify"
    )

    assert len(result["urls"]) == 2
    assert "example.com" in result["domains"]
    assert "evil.example.org" in result["domains"]