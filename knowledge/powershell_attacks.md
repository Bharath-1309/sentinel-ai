# PowerShell Attack Investigation Knowledge

## Suspicious PowerShell Execution

PowerShell can be abused by adversaries to execute commands, scripts, download payloads, or perform actions on a compromised system.

### Detection Indicators

- Encoded PowerShell commands
- Obfuscated PowerShell scripts
- PowerShell launched with unusual command-line arguments
- Download commands executed through PowerShell
- PowerShell spawning suspicious child processes
- PowerShell connecting to external hosts
- Commands containing execution or download-related parameters

### Investigation Steps

1. Identify the user and host that executed PowerShell.
2. Capture the complete PowerShell command line.
3. Check for encoded or obfuscated commands.
4. Identify any external domains or IP addresses contacted.
5. Examine child processes created by PowerShell.
6. Check downloaded files or payloads.
7. Check threat intelligence for contacted infrastructure.
8. Map the activity to the appropriate MITRE ATT&CK technique.

### Possible Risk

Suspicious PowerShell execution can indicate command execution, payload delivery, persistence, or post-compromise activity. Encoded or obfuscated commands combined with external network connections require additional investigation.