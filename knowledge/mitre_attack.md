# MITRE ATT&CK Knowledge Base

## T1110 — Brute Force

**Tactic:** Credential Access

**Description:**  
Adversaries may use repeated attempts to obtain valid account credentials.

**Common indicators:**
- Multiple failed authentication attempts
- Repeated login attempts against the same account
- Repeated authentication attempts from the same source IP
- Successful login following multiple failed attempts

**SOC investigation points:**
- Identify the source IP
- Identify the targeted username
- Count failed authentication attempts
- Check the time window of the attempts
- Determine whether a successful login occurred

---

## T1110.003 — Password Spraying

**Tactic:** Credential Access

**Description:**  
Adversaries may try a small number of commonly used passwords against many different accounts.

**Common indicators:**
- Multiple usernames targeted by the same source IP
- Authentication failures across several accounts
- Similar timestamps for attempts against different users
- Low number of attempts per individual account

**SOC investigation points:**
- Identify the source IP
- Identify all targeted usernames
- Count targeted accounts
- Examine the time window
- Check whether any account successfully authenticated