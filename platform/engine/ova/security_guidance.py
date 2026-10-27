"""Authoritative security guidance for OfflineVA reports.

Sources encoded here (for offline use on analyst workstation):
  - CIS Red Hat Enterprise Linux Benchmarks (common controls)
  - Red Hat Enterprise Linux Security Guide / hardening practices
  - NIST SP 800-53 / CIS Controls style network exposure rules
  - Vendor advisory URL patterns (access.redhat.com, Ubuntu USN, etc.)

Comments are issue-driven: empty string means "no finding / no comment".
Never emit filler like "OK for service accounts" on every row.
"""
from __future__ import annotations

from typing import Any, Optional
import re


# ---------------------------------------------------------------------------
# Port / service exposure guidance (CIS + RHEL Security Guide aligned)
# ---------------------------------------------------------------------------
# Each entry: (severity_rank, short_title, guidance)
# severity_rank: 0=critical exposure, 1=high, 2=medium, 3=info-only-if-world

_PORT_GUIDANCE: dict[str, tuple[int, str, str]] = {
    # Cleartext / legacy — CIS: disable unnecessary services
    "21": (0, "FTP",
           "CIS: FTP transmits credentials in cleartext. Disable vsftpd/proftpd or replace with SFTP/FTPS; "
           "if required, bind to management interface only and enforce TLS."),
    "23": (0, "Telnet",
           "CIS RHEL: Telnet must not be installed/enabled. Remove telnet-server; use SSH only."),
    "69": (1, "TFTP",
           "CIS: TFTP has no authentication. Disable tftp.socket/tftp.service unless PXE requires it, "
           "then isolate to provisioning VLAN."),
    "512": (0, "rexec", "CIS: r-services (rexec) are insecure. Remove rsh/rsh-server packages."),
    "513": (0, "rlogin", "CIS: rlogin is insecure. Remove rsh-server; enforce SSH with key auth."),
    "514": (0, "rsh", "CIS: rsh is insecure. Remove rsh-server package."),
    # Management plane
    "22": (1, "SSH",
           "RHEL Security Guide / CIS 5.2: SSH on 0.0.0.0 expands attack surface. Prefer ListenAddress on "
           "management IP; PermitRootLogin no; PasswordAuthentication no; allow only admin subnets in firewalld/iptables."),
    "3389": (1, "RDP",
             "RDP should not face untrusted networks. Restrict source IPs; prefer VPN jump host."),
    "5900": (1, "VNC", "VNC is often unencrypted. Disable or tunnel via SSH; restrict source networks."),
    "5901": (1, "VNC", "VNC is often unencrypted. Disable or tunnel via SSH; restrict source networks."),
    "5985": (1, "WinRM-HTTP", "WinRM over HTTP is cleartext. Use 5986/HTTPS or disable; restrict sources."),
    "5986": (2, "WinRM-HTTPS", "WinRM HTTPS — restrict to admin subnets only."),
    # Databases — CIS DB benchmarks + network isolation
    "3306": (1, "MySQL/MariaDB",
             "CIS MySQL/MariaDB: bind-address should be localhost or app subnet only. "
             "Do not expose 0.0.0.0:3306; enforce auth_plugin and TLS."),
    "5432": (1, "PostgreSQL",
             "CIS PostgreSQL: listen_addresses and pg_hba.conf must not allow unrestricted remote access. "
             "Bind to app network; require scram-sha-256 / TLS."),
    "1433": (1, "MSSQL", "SQL Server should not be world-reachable; restrict to app tier and use TLS."),
    "1521": (1, "Oracle", "Oracle listener should be restricted to application subnets only."),
    "27017": (1, "MongoDB", "MongoDB default bind is insecure historically. Bind to localhost/app net; require auth + TLS."),
    "6379": (1, "Redis",
             "Redis must not be exposed without AUTH and protected-mode. Bind 127.0.0.1 or private net; "
             "require requirepass / ACL and rename dangerous commands."),
    "9200": (1, "Elasticsearch",
             "Elasticsearch HTTP API must not be public. Enable xpack.security; bind to private network only."),
    "11211": (1, "Memcached", "Memcached has no auth. Bind localhost only or firewall strictly (historic amplification risk)."),
    # Directory / Windows
    "445": (1, "SMB", "SMB should not leave trusted zones. Disable SMBv1; restrict to file-server VLANs."),
    "135": (1, "MS-RPC", "MS-RPC endpoint mapper — restrict at perimeter; not for internet exposure."),
    "139": (1, "NetBIOS", "NetBIOS/SMB legacy — disable if unused; restrict sources."),
    "389": (1, "LDAP", "LDAP cleartext. Prefer LDAPS 636; restrict to identity-management network."),
    "636": (2, "LDAPS", "LDAPS — still restrict to IdM clients only."),
    "88": (2, "Kerberos", "Kerberos — expected on DCs; ensure only domain members can reach it."),
    # Web
    "80": (2, "HTTP",
           "Prefer HTTPS-only. If HTTP is required, redirect to 443 and do not serve authenticated content on 80."),
    "443": (3, "HTTPS", "HTTPS listener — ensure modern TLS (1.2+) and valid certificates (RHEL crypto policies)."),
    "8080": (2, "HTTP-alt", "Alternate HTTP port often used by apps/proxies. Confirm TLS termination and access control."),
    "8443": (2, "HTTPS-alt", "Alternate HTTPS — verify certificate and who may connect."),
    # Infra / orchestration
    "2375": (0, "Docker-API",
             "Docker API without TLS is root-equivalent. Never expose 2375; use 2376 with client certs or disable remote API."),
    "2376": (1, "Docker-TLS", "Docker TLS API — restrict to orchestrator nodes; audit client certificates."),
    "6443": (1, "kube-apiserver", "Kubernetes API must not be public. RBAC + network policy; admin VPN only."),
    "10250": (1, "kubelet", "Kubelet port — disable anonymous auth; restrict to control plane."),
    "2379": (1, "etcd", "etcd must not be reachable outside control plane; enable peer/client TLS."),
    "2380": (1, "etcd-peer", "etcd peer port — control-plane only."),
    "8500": (1, "Consul", "Consul HTTP API — enable ACLs; bind to private network; prefer HTTPS."),
    "8300": (2, "Consul-server", "Consul server RPC — cluster members only."),
    "8301": (2, "Consul-serf", "Consul Serf LAN — cluster members only."),
    "8600": (2, "Consul-DNS", "Consul DNS — restrict if not required cluster-wide."),
    "9090": (2, "Prometheus", "Prometheus often has no auth by default. Bind localhost or put behind SSO/reverse proxy."),
    "9100": (2, "node-exporter", "Node exporter — scrape from monitoring net only; do not expose publicly."),
    "9093": (2, "Alertmanager", "Alertmanager — restrict to monitoring network; enable auth if exposed."),
    "6789": (2, "Ceph/monitor", "Ceph monitor/msgr — storage cluster network only."),
    "111": (1, "RPCBind",
            "CIS: rpcbind expands attack surface (NFS/NIS). If NFS is not required, disable rpcbind.socket; "
            "otherwise firewall to NFS clients only."),
    "2049": (1, "NFS", "NFS — export only required paths with root_squash; restrict clients by IP; prefer NFSv4 + Kerberos."),
    "25": (2, "SMTP", "MTA on non-mail hosts is often unnecessary. If relay, restrict to app servers; enforce TLS."),
    "53": (2, "DNS", "DNS server should not be open resolver. Allow recursion only for trusted clients."),
    "161": (1, "SNMP", "SNMPv1/v2c use community strings (cleartext). Prefer SNMPv3; restrict sources; change defaults."),
    "162": (2, "SNMP-trap", "SNMP traps — restrict destination and community/credentials."),
    "123": (3, "NTP", "NTP/chrony — expected; ensure only trusted time sources (RHEL chrony.conf)."),
}


def _world_bound(ip: str) -> bool:
    return str(ip or "").strip() in ("0.0.0.0", "*", "::", "", "*:*")


def security_comment_connection(c: dict, local_ips: set[str], *, os_family: str = "redhat") -> str:
    """Return authoritative comment for one listener/connection, or '' if nothing notable."""
    st = str(c.get("state", "")).upper()
    sip = str(c.get("src_ip") or "")
    dip = str(c.get("dst_ip") or "")
    sport = str(c.get("src_port") or "")
    dport = str(c.get("dst_port") or "")
    proto = str(c.get("protocol") or "").lower()

    if st in ("LISTEN", "UNCONN"):
        port = sport
        guide = _PORT_GUIDANCE.get(port)
        world = _world_bound(sip)
        local_only = sip.startswith("127.") or sip in ("::1",)

        if guide:
            rank, title, text = guide
            if world and rank <= 2:
                return f"[{title}] {text}"
            if world and rank == 3:
                return f"[{title}] Listening on all interfaces — confirm firewall limits sources to trusted nets."
            if local_only and rank <= 1:
                return f"[{title}] Localhost-only bind — good isolation; still patch and harden the service."
            # Bound to specific non-local IP: only comment on high-risk services
            if not world and not local_only and rank <= 1:
                return f"[{title}] Bound to {sip}. {text}"
            return ""

        # Unknown service on all interfaces — real finding
        if world and port and port not in ("*",):
            return (
                f"Unidentified listener {proto}/{port} on all interfaces. "
                f"CIS: minimize network services — identify package (ss -tlnp), justify business need, "
                f"or stop/disable the unit and block in firewalld."
            )
        return ""

    if st == "ESTABLISHED":
        guide = _PORT_GUIDANCE.get(dport)
        if guide and guide[0] <= 1 and dip not in local_ips and not str(dip).startswith("127."):
            rank, title, text = guide
            return f"Active session to {title} ({dip}:{dport}). Ensure this path is authorized and encrypted."
        if dport in ("21", "23", "69") and dip not in local_ips:
            return "Cleartext protocol session in progress — replace with SSH/SFTP or terminate."
        return ""

    return ""


def security_comment_user(u: dict, *, os_family: str = "redhat") -> str:
    """CIS account hygiene — only when there is a real issue."""
    try:
        uid = int(str(u.get("uid") or "99999"))
    except ValueError:
        uid = 99999
    user = str(u.get("username") or "")
    shell = str(u.get("shell") or "")
    home = str(u.get("home") or "")

    nologin = shell in (
        "/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false",
        "/bin/nologin", "/dev/null",
    )

    # CIS 5.4.2 / 6.2.x: no UID 0 except root
    if uid == 0 and user != "root":
        return (
            "CIS 5.4.2 / RHEL: only root may have UID 0. "
            f"Account '{user}' has UID 0 — remove or assign unique non-zero UID immediately."
        )

    # Interactive system accounts (UID < 1000) with login shells — CIS
    if uid < 1000 and uid != 0 and not nologin and shell not in ("",):
        if shell in ("/bin/bash", "/bin/sh", "/bin/zsh", "/bin/csh", "/bin/ksh"):
            return (
                f"CIS: system account '{user}' (UID {uid}) has interactive shell {shell}. "
                "Set shell to /sbin/nologin unless interactive admin use is required."
            )

    # Cloud bootstrap accounts left enabled
    if user in ("cloud-user", "centos", "ec2-user", "fedora", "admin") and not nologin:
        return (
            f"Bootstrap account '{user}' still has interactive shell. "
            "RHEL cloud images: disable password auth, restrict to SSH keys, or lock after provisioning "
            "(passwd -l / usermod -s /sbin/nologin) per hardening baseline."
        )

    # Root with non-standard shell is informational only if weird
    if user == "root" and shell not in ("/bin/bash", "/bin/sh", "/sbin/nologin", ""):
        return f"Root shell is {shell} — confirm this matches organizational standard."

    # Empty or world-writable home hints are handled elsewhere; skip noise
    return ""


def security_comment_route(r: dict) -> str:
    dest = str(r.get("destination") or "")
    gw = str(r.get("gateway") or "")
    iface = str(r.get("interface") or "")
    if dest in ("default", "0.0.0.0/0", "::/0") and gw:
        return (
            f"Default route via {gw}"
            + (f" ({iface})" if iface else "")
            + ". Confirm this is the approved edge gateway; unexpected defaults enable traffic redirection."
        )
    return ""


def security_comment_process(path: str) -> str:
    p = (path or "").lower()
    if any(x in p for x in ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/")) and (
        p.endswith(".sh") or "/python" in p or "/perl" in p or "/nc" in p or "ncat" in p
    ):
        return (
            "Root process running from non-standard path (tmp/home). "
            "Investigate for persistence (cron, systemd user units, ld preload)."
        )
    if re.search(r"(?:^|/)(nc|ncat|netcat|socat)(?:\s|$)", p):
        return "Netcat/socat running as root — high risk if reverse shell; validate change ticket."
    if "/.ssh/" in p and "sshd" not in p:
        return "Root process referencing .ssh path — verify legitimate key operations."
    return ""


def security_comment_cron(job: str) -> str:
    j = (job or "").lower()
    if any(x in j for x in ("curl ", "wget ", "| sh", "| bash", "/dev/tcp/", "base64 -d")):
        return (
            "Scheduled job invokes download-and-execute pattern. "
            "Treat as high priority: verify script integrity and source URL."
        )
    if "/tmp/" in j or "/dev/shm/" in j:
        return "Cron references temporary filesystem — unusual for production; review."
    return ""


# ---------------------------------------------------------------------------
# Vulnerability / remediation guidance (vendor-oriented)
# ---------------------------------------------------------------------------

def redhat_advisory_url(advisory: str) -> str:
    """Build access.redhat.com security advisory URL from RHSA/RHBA/RHEA id."""
    adv = (advisory or "").strip()
    m = re.search(r"((?:RHSA|RHBA|RHEA)-\d{4}:\d+)", adv, re.I)
    if not m:
        return ""
    aid = m.group(1).upper()
    # Red Hat portal pattern
    return f"https://access.redhat.com/errata/{aid}"


def ubuntu_usn_url(advisory: str) -> str:
    m = re.search(r"(USN-\d+-\d+)", advisory or "", re.I)
    if not m:
        return ""
    return f"https://ubuntu.com/security/notices/{m.group(1).upper()}"


def debian_dsa_url(advisory: str) -> str:
    m = re.search(r"(DSA-\d+)", advisory or "", re.I)
    if not m:
        return ""
    return f"https://security-tracker.debian.org/tracker/{m.group(1).upper()}"


def vendor_advisory_url(advisory: str, os_family: str = "redhat") -> str:
    fam = (os_family or "").lower()
    if "ubuntu" in fam or "debian" in fam:
        return ubuntu_usn_url(advisory) or debian_dsa_url(advisory)
    return redhat_advisory_url(advisory) or ubuntu_usn_url(advisory) or debian_dsa_url(advisory)


def remediation_for_finding(
    *,
    package: str,
    advisory: str,
    fixed_evr: str,
    installed_evr: str,
    solution: str,
    os_family: str = "redhat",
    os_version: str = "",
) -> str:
    """Build a concrete remediation line using vendor advisory + package update command."""
    parts: list[str] = []
    adv = (advisory or "").strip()
    url = vendor_advisory_url(adv, os_family)
    fam = (os_family or "").lower()

    if adv:
        parts.append(adv)
    if url:
        parts.append(url)

    # Concrete package manager action
    pkg = (package or "").strip().split()[0] if package else ""
    if pkg and pkg not in ("unknown", "—"):
        if "ubuntu" in fam or "debian" in fam:
            cmd = f"apt-get update && apt-get install --only-upgrade {pkg}"
        elif "sles" in fam or "suse" in fam:
            cmd = f"zypper patch --cve=...  # or: zypper update {pkg}"
        else:
            # RHEL/CentOS/Rocky/Alma
            major = ""
            m = re.search(r"(\d+)", os_version or "")
            if m:
                major = m.group(1)
            if major and int(major) >= 8:
                cmd = f"dnf update -y {pkg}"
            else:
                cmd = f"yum update -y {pkg}"
        if fixed_evr:
            parts.append(f"target version ≥ {fixed_evr}")
        parts.append(f"run: {cmd}")
    elif solution and solution.strip():
        parts.append(solution.strip()[:240])
    elif adv:
        parts.append("Apply the vendor advisory packages, then reboot if kernel/glibc/openssl requires it.")

    if installed_evr and fixed_evr:
        parts.append(f"installed={installed_evr}")

    return " | ".join(parts)


def security_comment_vulnerability(
    *,
    severity: str,
    package: str,
    advisory: str,
    cves: list[str],
    kev: bool = False,
    status: str = "",
    os_family: str = "redhat",
) -> str:
    """Auditor note on a vulnerability group — evidence-based, not generic."""
    bits: list[str] = []
    sev = (severity or "").title()
    url = vendor_advisory_url(advisory, os_family)

    if kev:
        bits.append("CISA KEV: actively exploited — patch as emergency change")
    if sev == "Critical":
        bits.append("Critical severity: prioritize within emergency SLA; isolate host if exploit is public")
    elif sev == "High":
        bits.append("High severity: schedule urgent patch window; verify exploitability on this build")

    if advisory:
        bits.append(f"Vendor fix: {advisory}")
    if url:
        bits.append(url)

    pkg = (package or "").split(",")[0].strip()
    if pkg and any(x in pkg.lower() for x in ("openssl", "openssh", "kernel", "glibc", "sudo", "polkit", "systemd")):
        bits.append(f"Core component ({pkg}) — regression-test and consider reboot after update")

    st = (status or "").lower()
    if "reboot" in st:
        bits.append("Reboot required for full remediation")
    if "no_fix" in st or "no fix" in st:
        bits.append("No vendor fix yet — apply compensating controls (WAF, network block, disable feature)")

    return " | ".join(bits[:4])
