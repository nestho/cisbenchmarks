# Official EGK Master Assessment Workbook Standard (.xlsx)

- **Governing Standard**: EGK Security Oversight & Regulatory Compliance Specification
- **Target Systems**: Telecom Core, BSS, OSS, Ericsson ENM, Edge Signatures, Banking Backbones
- **Format**: 15-Sheet OpenPyXL / Excelize Workbook
- **Review Protocol**: 3-Party Regulatory Sign-off Workflow:
  1. `Security Comments`: Authored by HardenX / Lead Security Auditor (cites evidence IDs).
  2. `Owner Comments`: Authored by System Owner / Ops Engineer (justification of business needs).
  3. `Security Reviews`: Authored by Regulatory Supervisor / Security Board (accepted/rejected).

## Sheet Schema & Mapping
1. `Cover`: Title, Classification (Confidential), Operator, Target Host.
2. `Document Information`: Fixed Generation Dates, Publisher, Review Stage.
3. `Host information`: Hostname, OAM IP Address, MAC Addresses, Kernel, Open Ports.
4. `Firewall Assessment`: Connection Matrix (VRF, Interface, Protocol, Source, Destination).
5. `Summary`: Vulnerability Severity Counters, CIS Compliance Scoring Donuts.
6. `Vulnerabilities`: CVEs, Vendor Errata (RHSA/USN), VEX Verdict, CVSS, Evidence Citations.
7. `Compliance`: CIS Recommendation ID, Title, Profile (Level 1/2), Test Result, Remediation.
8. `Remediations`: Target package versions, configuration hardening scripts.
9. `Users`: Accounts, UID/GID, Shell, Home, Password Aging, Sudoers NOPASSWD.
10. `Routes`: Kernel Route Table, Gateways, Direct-Connected Flags.
11. `Groups`: System Groups, GIDs, Membership.
12. `Cron Jobs`: Crontabs, Systemd Timers.
13. `Processes by root`: Active Daemons running as UID 0, Systemd Units.
14. `Environment`: System & Process Environments, Masked Secrets.
15. `ssh known hosts`: Authorized Keys, Known Hosts, Key Types, Fingerprints.
