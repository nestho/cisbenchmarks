# Scanner Design

## Agentless connectors
- SSH: execute commands, fetch files via SFTP; supports key/password auth, bastion.
- WinRM: PowerShell remoting.
- Network: SSH + vendor-specific parsers (Cisco IOS, Juniper, Palo Alto, etc.).
- Cloud: AWS SDK, Azure SDK, GCP SDK with read-only roles.

## Optional agent
- Go binary, runs as service, registers to control plane over mTLS.
- Used for deep checks, offline targets, or environments without SSH/WinRM.

## Check execution
- Parallel per target with configurable concurrency.
- Timeout per check; capture exit code, stdout, stderr, duration.
- Evidence stored as blob (command + output + timestamp + hash).

## Safety
- Read-only commands only by default.
- Command allowlist per benchmark; block destructive patterns.
- Dry-run mode lists commands without executing.
