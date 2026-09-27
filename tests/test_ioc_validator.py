from analyzer.ioc_validator import (
    normalize_ioc,
    is_valid_ip,
    is_valid_domain,
    is_valid_url,
    detect_hash_type,
    classify_ioc,
)


def test_normalize_ioc():

    assert normalize_ioc(
        "  8.8.8.8  "
    ) == "8.8.8.8"


def test_valid_ipv4():

    assert is_valid_ip(
        "192.168.1.50"
    ) is True


def test_valid_ipv6():

    assert is_valid_ip(
        "2001:db8::1"
    ) is True


def test_invalid_ip():

    assert is_valid_ip(
        "999.999.999.999"
    ) is False


def test_valid_domain():

    assert is_valid_domain(
        "example.com"
    ) is True


def test_valid_subdomain():

    assert is_valid_domain(
        "login.example.com"
    ) is True


def test_invalid_domain():

    assert is_valid_domain(
        "not a domain"
    ) is False


def test_valid_http_url():

    assert is_valid_url(
        "http://example.com/login"
    ) is True


def test_valid_https_url():

    assert is_valid_url(
        "https://example.com/path"
    ) is True


def test_invalid_url():

    assert is_valid_url(
        "example.com/path"
    ) is False


def test_detect_md5():

    assert detect_hash_type(
        "d41d8cd98f00b204e9800998ecf8427e"
    ) == "md5"


def test_detect_sha1():

    assert detect_hash_type(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ) == "sha1"


def test_detect_sha256():

    assert detect_hash_type(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    ) == "sha256"


def test_invalid_hash():

    assert detect_hash_type(
        "not-a-hash"
    ) is None


def test_classify_ip():

    assert classify_ioc(
        "8.8.8.8"
    ) == "ip"


def test_classify_domain():

    assert classify_ioc(
        "example.com"
    ) == "domain"


def test_classify_url():

    assert classify_ioc(
        "https://example.com/login"
    ) == "url"


def test_classify_hash():

    assert classify_ioc(
        "d41d8cd98f00b204e9800998ecf8427e"
    ) == "hash"


def test_classify_unknown():

    assert classify_ioc(
        "not-an-ioc"
    ) is None