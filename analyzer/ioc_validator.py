import hashlib
import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


SUPPORTED_HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}


def normalize_ioc(value: str) -> str:
    return value.strip()


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(
        DOMAIN_PATTERN.fullmatch(value)
    )


def is_valid_url(value: str) -> bool:

    try:
        parsed = urlparse(value)

        return (
            parsed.scheme.lower()
            in {"http", "https"}
            and bool(parsed.netloc)
        )

    except ValueError:
        return False


def detect_hash_type(value: str) -> str | None:

    normalized = value.lower()

    hash_type = SUPPORTED_HASH_LENGTHS.get(
        len(normalized)
    )

    if hash_type is None:
        return None

    try:
        int(normalized, 16)
    except ValueError:
        return None

    return hash_type


def classify_ioc(value: str) -> str | None:

    value = normalize_ioc(value)

    if not value:
        return None

    if is_valid_ip(value):
        return "ip"

    if is_valid_url(value):
        return "url"

    if is_valid_domain(value):
        return "domain"

    hash_type = detect_hash_type(value)

    if hash_type:
        return "hash"

    return None