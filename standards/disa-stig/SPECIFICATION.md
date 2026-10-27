# DISA STIG Standard Specification (XCCDF & CKL)

- **Authority**: Defense Information Systems Agency (DISA)
- **Severity Categories**:
  - **CAT I (High Severity)**: Any vulnerability that directly allows unauthorized root/admin access, bypass of core firewalls, or immediate arbitrary code execution.
  - **CAT II (Medium Severity)**: Any vulnerability that facilitates unauthorized privilege elevation, unauthorized disclosure of sensitive data, or security boundary bypass.
  - **CAT III (Low Severity)**: Inadequate configuration practices that increase attack surface or compromise auditing integrity.

## Checklist (CKL) Schema
HardenX supports exporting findings to standard DISA `.ckl` XML format for official submission into STIG Viewer.
