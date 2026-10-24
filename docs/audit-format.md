# Audit Format (canonical)

Native format: YAML. Example:

```yaml
benchmark:
  id: cis-apache-2.4
  title: CIS Apache HTTP Server 2.4 Benchmark
  version: 1.3.1
  technology: Apache HTTP Server
  os: Linux

controls:
  - id: 2.2
    title: Enable the Log Config Module
    scoring: scored
    profile: [level1, level2]
    checks:
      - type: command
        command: "apachectl -M 2>/dev/null | grep -i log_config"
        expected: "log_config_module"
        regex: "log_config_module\\s*\\(shared\\)"
      - type: file
        path: /etc/httpd/conf/httpd.conf
        contains: "LoadModule log_config_module"
    remediation: "Enable mod_log_config and restart Apache."
```

Nessus `.audit` files are parsed into the same model. Field mapping documented in
`docs/nessus-audit-mapping.md` (todo).

## Check types
- `command` — run shell command, match stdout/exit code.
- `file` — read file, match content/permissions/owner.
- `registry` — Windows registry value.
- `service` — service running/enabled.
- `package` — package installed/version.
- `api` — HTTP API response.
- `cloud` — cloud resource property.
- `script` — custom Go/Python plugin.
