# Windows Authentication Attack Knowledge

## Credential Attacks Against Windows Authentication

Attackers may target Windows authentication services to obtain or abuse valid credentials.

### Detection Indicators

- Multiple failed Windows authentication attempts
- Repeated failures against the same account
- Authentication failures from unusual source hosts
- Multiple accounts targeted from the same source
- Successful authentication following repeated failures
- Authentication activity outside normal user behavior

### Investigation Steps

1. Identify the source host or IP address.
2. Identify the targeted username or usernames.
3. Count authentication failures.
4. Examine the time window.
5. Check whether authentication eventually succeeded.
6. Check whether multiple accounts were targeted.
7. Review source IP or host threat intelligence where available.
8. Map the activity to the appropriate MITRE ATT&CK technique.

### Possible Risk

Repeated authentication failures may indicate brute force, password spraying, or other credential attacks. A successful authentication following suspicious failures can indicate possible account compromise and requires additional investigation.