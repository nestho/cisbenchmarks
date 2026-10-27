# OASIS CSAF 2.0 & Vulnerability Exploitability eXchange (VEX) Standard

- **Standard**: OASIS Common Security Advisory Framework (CSAF) Version 2.0
- **Profiles Implemented**:
  1. **CSAF Base**: Document metadata, publisher, tracking history.
  2. **Security Advisory**: Vendor errata notifications (RHSA, USN, DSA, SUSE).
  3. **VEX (Vulnerability Exploitability eXchange)**: Machine-readable vendor vulnerability states:
     - `known_affected`: Vulnerability exists and is exploitable.
     - `fixed`: Patched in the indicated version.
     - `under_investigation`: Vendor analyzing impact on product build.
     - `known_not_affected`: Vendor confirms immunity with justification flags:
       - `component_not_present`
       - `vulnerable_code_not_present`
       - `vulnerable_code_not_in_execute_path`
       - `vulnerable_code_cannot_be_controlled_by_adversary`
       - `inline_mitigations_already_exist`

## Engine Application
HardenX parses vendor CSAF VEX records from Red Hat, SUSE, and Canonical to guarantee **zero false positives** on backported patches and compiler-hardened binaries.
