import re
from urllib.parse import urlparse


class PhishingIntelligence:

    URL_PATTERN = r"https?://[^\s<>\"]+"

    def extract_indicators(self, message):

        urls = re.findall(
            self.URL_PATTERN,
            message,
            re.IGNORECASE
        )

        domains = []

        for url in urls:
            hostname = urlparse(url).hostname

            if hostname and hostname not in domains:
                domains.append(hostname)

        return {
            "urls": urls,
            "domains": domains
        }