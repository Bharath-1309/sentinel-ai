# Phishing Attack Investigation Knowledge

## Phishing

Phishing uses deceptive messages or websites to trick users into revealing credentials, financial information, or other sensitive data.

### Detection Indicators

- Urgent requests for account verification
- Requests for usernames, passwords, OTPs, or verification codes
- Requests for payment or financial information
- Suspicious or shortened URLs
- IP addresses used instead of domains
- Lookalike or impersonation domains
- Punycode domains
- Excessive subdomains
- Suspicious URL encoding
- Unusual web ports

### Investigation Steps

1. Extract URLs and domains from the message.
2. Inspect the domain for impersonation or lookalike characteristics.
3. Check URL structure and encoding.
4. Identify credential or financial information requests.
5. Identify urgency indicators.
6. Check domain or IP reputation using threat intelligence.
7. Determine whether the user interacted with the suspicious link.
8. Map the activity to the appropriate MITRE ATT&CK technique.

### Possible Risk

Phishing can lead to credential theft, financial fraud, malware delivery, or unauthorized account access. Messages requesting credentials or financial information combined with suspicious URLs should receive additional investigation.