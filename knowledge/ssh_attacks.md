# SSH Attack Investigation Knowledge

## SSH Brute Force

SSH brute force involves repeated authentication attempts against an account or service.

### Detection Indicators

- Multiple failed SSH authentication attempts
- Repeated attempts from the same source IP
- Multiple attempts against the same username
- Authentication failures concentrated within a short time window
- Successful login after repeated failures

### Investigation Steps

1. Identify the source IP address.
2. Identify the targeted username.
3. Count failed authentication attempts.
4. Determine the time window of the attempts.
5. Check whether authentication eventually succeeded.
6. Check threat intelligence for the source IP.
7. Map the activity to the appropriate MITRE ATT&CK technique.

### Possible Risk

Repeated failed attempts alone may indicate credential attacks. A successful login following multiple failures can indicate possible account compromise and should receive additional investigation.

---

## SSH Password Spraying

Password spraying attempts a small number of passwords against multiple accounts.

### Detection Indicators

- Same source IP targeting multiple usernames
- Authentication failures across several accounts
- Similar timestamps across targeted accounts
- Relatively few attempts against each individual account

### Investigation Steps

1. Identify the source IP.
2. Identify all targeted usernames.
3. Count the number of targeted accounts.
4. Examine the attack time window.
5. Check for successful authentication.
6. Check source IP threat intelligence.
7. Map the activity to MITRE ATT&CK.

### Possible Risk

Password spraying can affect multiple accounts simultaneously. A successful authentication should trigger additional investigation for possible account compromise.