"""Local-only collector commands shared by the UI and exported examples."""

RPM_FAMILIES = frozenset({'redhat', 'suse', 'huawei', 'oracle', 'rocky', 'alma', 'centos', 'amazon', 'fedora', 'opensuse', 'openeuler'})
DEB_FAMILIES = frozenset({'debian', 'ubuntu', 'mint', 'kali'})
SUSE_FAMILIES = frozenset({'suse', 'opensuse'})
RPM_FORMAT = r'%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{INSTALLTIME}|%{BUILDTIME}'
RPM_SIGNATURE = r'%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|'
RPM_ID = r'%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|'
LABELS = {
    'rpm': 'RPM / DNF / YUM', 'suse': 'SUSE / RPM / Zypper',
    'deb': 'Debian / Ubuntu / Mint / Kali - DPKG / APT',
    'alpine': 'Alpine - APK', 'arch': 'Arch - Pacman',
    'auto': 'Automatic selection from local OS / package database',
}
RELEASE_FILES = {
    'rpm': '/usr/lib/os-release /etc/os-release /etc/redhat-release /etc/centos-release /etc/oracle-release /etc/rocky-release /etc/almalinux-release /etc/fedora-release /etc/system-release /etc/system-release-cpe /etc/euleros-release /etc/hce-release /etc/openEuler-release /etc/huawei-release',
    'suse': '/usr/lib/os-release /etc/os-release /etc/SuSE-release',
    'deb': '/usr/lib/os-release /etc/os-release /etc/debian_version /etc/lsb-release',
    'alpine': '/usr/lib/os-release /etc/os-release /etc/alpine-release',
    'arch': '/usr/lib/os-release /etc/os-release /etc/arch-release',
}
FAMILIES = {'rpm': 'RPM_DNF_YUM', 'suse': 'SUSE_RPM_ZYPPER', 'deb': 'DEB_DPKG_APT', 'alpine': 'ALPINE_APK', 'arch': 'ARCH_PACMAN'}
# Never source/eval configuration or invoke network-facing repository clients.
# TIMEOUT_BIN is set so hung sockets/daemons cannot stall the whole collector.
HEADER = r'''(
export LC_ALL=C
TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout 5"
echo "===== VA_OFFLINE_INVENTORY_BEGIN ====="
echo "===== COLLECTION_TIME_UTC ====="
date -u '+%Y-%m-%dT%H:%M:%SZ'
echo "===== HOSTNAME ====="
hostname 2>/dev/null || uname -n 2>/dev/null || echo "unknown-host"
echo "===== KERNEL_RUNNING ====="
uname -r 2>/dev/null
uname -a 2>/dev/null
echo "===== MACHINE_ARCHITECTURE ====="
uname -m 2>/dev/null
echo "===== SYSTEM_LOAD_SNAPSHOT ====="
# Context only — high load does not change collection policy
if [ -r /proc/loadavg ]; then cat /proc/loadavg; else uptime 2>/dev/null; fi
echo "===== INIT_SYSTEM ====="
if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
    echo "systemd"
elif [ -d /etc/init.d ] && [ ! -d /run/systemd/system ]; then
    echo "sysvinit_or_upstart"
else
    echo "unknown"
fi
echo "===== COLLECTOR_RUNTIME ====="
echo "shell=$0"
echo "timeout_helper=${TIMEOUT_BIN:-none}"
echo "uid=$(id -u 2>/dev/null)"
echo "user=$(id -un 2>/dev/null)"
'''
# Container / orchestration platform detection — read-only, timeout-bounded.
# Helps scope VA: runtime packages, control-plane ports, and nested-container hosts.
PLATFORM_INTEL = r'''
echo "===== VA_CONTAINER_INVENTORY_BEGIN ====="
echo "===== CONTAINER_PROCESS_SCAN ====="
# Single /proc scan via pgrep; safe under load
CONTAINER_PROCS="dockerd containerd containerd-shim containerd-shim-runc-v2 docker-proxy podman conmon catatonit netavark slirp4netns kubelet kube-proxy kube-apiserver kube-scheduler kube-controller-manager etcd crio cri-o hyperkube lxc-start lxcfs lxd nomad runc buildkitd"
for p in $CONTAINER_PROCS; do
    if command -v pgrep >/dev/null 2>&1; then
        out=$(pgrep -fla "$p" 2>/dev/null)
    else
        out=$(ps -ef 2>/dev/null | awk -v pat="$p" 'index($0,pat)>0 && $0 !~ /awk/ {print}')
    fi
    if [ -n "$out" ]; then
        echo "--- FOUND: $p ---"
        echo "$out"
    fi
done
echo "===== SYSTEMD_SERVICE_STATE ====="
if command -v systemctl >/dev/null 2>&1; then
    SERVICES="docker docker.socket containerd podman podman.socket kubelet crio crio.socket lxd nomad atomic-openshift-node origin-node"
    for s in $SERVICES; do
        state=$(${TIMEOUT_BIN:-} systemctl is-active "$s" 2>/dev/null)
        enab=$(${TIMEOUT_BIN:-} systemctl is-enabled "$s" 2>/dev/null)
        if [ -n "$state" ] || [ -n "$enab" ]; then
            echo "$s|active=$state|enabled=$enab"
        fi
    done
else
    echo "systemctl not available (pre-systemd init or restricted PATH)"
    if [ -d /etc/init.d ]; then
        for s in docker kubelet containerd podman lxd; do
            [ -x "/etc/init.d/$s" ] && echo "init.d/$s|present=yes"
        done
    fi
fi
echo "===== LISTENING_PORTS_OF_INTEREST ====="
# Orchestration-relevant ports only — not a full port scan
PORT_REGEX=':(2375|2376|2377|4243|4244|6443|8443|10250|10251|10252|10255|2379|2380|4789|8472|30000|30001) '
if command -v ss >/dev/null 2>&1; then
    ${TIMEOUT_BIN:-} ss -tlnp 2>/dev/null | grep -E "$PORT_REGEX" || true
elif command -v netstat >/dev/null 2>&1; then
    ${TIMEOUT_BIN:-} netstat -tlnp 2>/dev/null | grep -E "$PORT_REGEX" || true
else
    echo "no ss/netstat available"
fi
echo "===== CONTAINER_PACKAGE_MATCH ====="
if command -v rpm >/dev/null 2>&1; then
    rpm -qa 2>/dev/null | grep -Ei 'docker|podman|kubernetes|kubelet|kubeadm|kubectl|containerd|cri-o|crio|openshift|lxc|nomad|runc|buildah|skopeo' || true
fi
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}|${Version}|${Status}\n' 2>/dev/null | grep -Ei 'docker|podman|kubernetes|kubelet|kubeadm|kubectl|containerd|cri-o|crio|lxc|nomad|runc' || true
fi
echo "===== NON_PKG_BINARY_VERSIONS ====="
# Manually installed / static binaries not always in the package DB
for bin in docker podman containerd kubelet kubeadm kubectl crio cri-o nomad etcd runc buildah skopeo; do
    p=$(command -v "$bin" 2>/dev/null)
    if [ -n "$p" ]; then
        ver=$(${TIMEOUT_BIN:-} "$p" --version 2>&1 | head -1)
        echo "$bin|$p|$ver"
    fi
done
echo "===== FILESYSTEM_INDICATORS ====="
# Stat only — no find/du traversal
for f in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /etc/docker/daemon.json \
         /var/lib/containers /var/lib/docker /etc/kubernetes /var/lib/kubelet \
         /etc/origin /etc/crio /etc/crio/crio.conf /var/lib/etcd /etc/nomad.d \
         /var/snap/docker /var/snap/microk8s; do
    if [ -e "$f" ]; then
        info=$(stat -c '%U:%G %a %Y' "$f" 2>/dev/null || stat -f '%Su:%Sg %Mp%Lp %m' "$f" 2>/dev/null)
        echo "EXISTS: $f ($info)"
    fi
done
echo "===== CGROUP_CONTAINER_HINTS ====="
# Host itself running inside a container (scoping / nested environments)
if [ -r /proc/1/cgroup ]; then
    grep -Eo 'docker|kubepods|lxc|containerd|libpod' /proc/1/cgroup 2>/dev/null | sort -u || true
fi
if [ -f /.dockerenv ]; then
    echo "dockerenv_present=yes"
fi
echo "===== VA_CONTAINER_INVENTORY_END ====="
'''
END = PLATFORM_INTEL + 'echo "===== VA_OFFLINE_INVENTORY_END ====="\n)\n'

# Only configuration evidence. URL/userinfo/query tokens and auth files omitted.
INI_FILTER = r"""awk '
/^[[:space:]]*\[[^]]+\]/ { print; next }
/^[[:space:]]*(name|baseurl|mirrorlist|metalink|gpgkey)[[:space:]]*=/ {
    sub(/=.*/, "=[OMITTED]"); print; next
}
/^[[:space:]]*(enabled|autorefresh|gpgcheck|repo_gpgcheck|sslverify|priority|type)[[:space:]]*=/ {
    sub(/[[:space:]]*[#;].*$/, ""); print
}' "$f"
"""
TEXT_FILTER = r"""awk '
/^[[:space:]]*#/ { next }
{
    gsub(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^[:space:]]+/, "[URI_OMITTED]")
    print
}' "$f"
"""


def _repos(marker: str, paths: str, ini: bool = False) -> str:
    return ('echo "===== ' + marker + ' ====="\nfor f in ' + paths
            + '; do\n    [ -r "$f" ] || continue\n    echo "--- $f ---"\n'
            + (INI_FILTER if ini else TEXT_FILTER) + 'done\n')


RPM_REPOS = _repos('RPM_REPOSITORY_CONFIG_EVIDENCE', '/etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/*.repo', True)
SUSE_REPOS = _repos('SUSE_REPOSITORY_CONFIG_EVIDENCE', '/etc/zypp/zypp.conf /etc/zypp/repos.d/*.repo', True)
RPM = '''echo "===== RPM_INVENTORY_NEVRA ====="
if command -v rpm >/dev/null 2>&1; then
''' + "    rpm -qa --qf '" + RPM_FORMAT + r"\n'" + ''' || {
        echo "===== COLLECTOR_WARNINGS ====="
        echo "failed: RPM_INVENTORY_QUERY"
    }
else
    echo "===== COLLECTOR_WARNINGS ====="
    echo "failed: RPM_NOT_AVAILABLE"
fi
echo "===== RPM_SIGNATURE_METADATA ====="
if command -v rpm >/dev/null 2>&1; then
''' + "    rpm -qa --qf '" + RPM_ID + RPM_SIGNATURE + r"\n' 2>/dev/null" + ''' || {
        echo "===== COLLECTOR_WARNINGS ====="
        echo "RPM_SIGNATURE_QUERY_UNSUPPORTED"
    }
fi
'''
DEB = _repos('APT_REPOSITORY_CONFIG_EVIDENCE', '/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources') + '''echo "===== DPKG_ARCHITECTURE ====="
if command -v dpkg >/dev/null 2>&1; then
    echo "NATIVE_ARCHITECTURE=$(dpkg --print-architecture)"
    dpkg --print-foreign-architectures 2>/dev/null | while IFS= read -r arch; do
        [ -n "$arch" ] && echo "FOREIGN_ARCHITECTURE=$arch"
    done
fi
echo "===== DPKG_INVENTORY ====="
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${binary:Package}|${Version}|${Architecture}|${source:Package}|${source:Version}|${Maintainer}|${Status}\\n' || {
        echo "===== COLLECTOR_WARNINGS ====="
        echo "DPKG_QUERY_FAILED_USING_STATUS_FALLBACK"
    }
fi
# Also preserves source mapping on older dpkg versions.
echo "===== DPKG_STATUS_DATABASE ====="
if [ -r /var/lib/dpkg/status ]; then
    awk '/^(Package|Status|Version|Architecture|Source|Maintainer|Origin):/ || /^$/ { print }' /var/lib/dpkg/status
else
    echo "===== COLLECTOR_WARNINGS ====="
    echo "DPKG_STATUS_DATABASE_NOT_READABLE"
fi
'''
APK = '''echo "===== APK_ARCHITECTURE ====="
if command -v apk >/dev/null 2>&1; then
    apk --print-arch 2>/dev/null
fi
''' + _repos('APK_REPOSITORY_CONFIG_EVIDENCE', '/etc/apk/repositories') + r'''echo "===== APK_INVENTORY ====="
if [ -r /lib/apk/db/installed ]; then
    awk '
    BEGIN { P=""; V=""; A=""; O=""; M=""; T="" }
    /^P:/ { P=substr($0,3) }
    /^V:/ { V=substr($0,3) }
    /^A:/ { A=substr($0,3) }
    /^o:/ { O=substr($0,3) }
    /^m:/ { M=substr($0,3) }
    /^t:/ { T=substr($0,3) }
    /^$/ {
        if (P != "") print P "|" V "|" A "|" O "|" M "|" T
        P=""; V=""; A=""; O=""; M=""; T=""
    }
    END { if (P != "") print P "|" V "|" A "|" O "|" M "|" T }
    ' /lib/apk/db/installed
else
    echo "===== COLLECTOR_WARNINGS ====="
    echo "failed: APK_DATABASE_NOT_AVAILABLE"
fi
'''
PACMAN = _repos('PACMAN_REPOSITORY_CONFIG_EVIDENCE', '/etc/pacman.conf /etc/pacman.d/mirrorlist') + r'''echo "===== PACMAN_INVENTORY ====="
FOUND_PACMAN_DB=0
for f in /var/lib/pacman/local/*/desc; do
    [ -r "$f" ] || continue
    FOUND_PACMAN_DB=1
    awk '
    BEGIN { key=""; name=""; version=""; base=""; arch=""; builddate=""; installdate=""; packager=""; validation="" }
    /^%NAME%$/ { key="NAME"; next }
    /^%VERSION%$/ { key="VERSION"; next }
    /^%BASE%$/ { key="BASE"; next }
    /^%ARCH%$/ { key="ARCH"; next }
    /^%BUILDDATE%$/ { key="BUILDDATE"; next }
    /^%INSTALLDATE%$/ { key="INSTALLDATE"; next }
    /^%PACKAGER%$/ { key="PACKAGER"; next }
    /^%VALIDATION%$/ { key="VALIDATION"; next }
    /^%/ { key=""; next }
    /^[[:space:]]*$/ { key=""; next }
    {
        if (key == "NAME") name=$0
        else if (key == "VERSION") version=$0
        else if (key == "BASE") base=$0
        else if (key == "ARCH") arch=$0
        else if (key == "BUILDDATE") builddate=$0
        else if (key == "INSTALLDATE") installdate=$0
        else if (key == "PACKAGER") packager=$0
        else if (key == "VALIDATION") validation=validation (validation == "" ? "" : ",") $0
    }
    END { if (name != "") print name "|" version "|" base "|" arch "|" builddate "|" installdate "|" packager "|" validation }
    ' "$f"
done
if [ "$FOUND_PACMAN_DB" -eq 0 ]; then
    echo "===== COLLECTOR_WARNINGS ====="
    echo "PACMAN_LOCAL_DATABASE_NOT_READABLE"
    echo "===== PACMAN_INVENTORY_FALLBACK ====="
    if command -v pacman >/dev/null 2>&1; then
        pacman -Q || {
            echo "===== COLLECTOR_WARNINGS ====="
            echo "failed: PACMAN_QUERY"
        }
    else
        echo "===== COLLECTOR_WARNINGS ====="
        echo "failed: PACMAN_NOT_AVAILABLE"
    fi
fi
'''


def collector_profile(family: str) -> str:
    if family in SUSE_FAMILIES:
        return 'suse'
    if family in RPM_FAMILIES:
        return 'rpm'
    if family in DEB_FAMILIES:
        return 'deb'
    if family in {'auto', 'arch', 'alpine'}:
        return family
    raise ValueError(f'No collector is defined for {family!r}')


def collector_label(family: str) -> str:
    return LABELS[collector_profile(family)]


def _body(profile: str) -> str:
    release = ('echo "===== FAMILY ====="\necho "' + FAMILIES[profile]
               + '"\necho "===== OS_RELEASE ====="\nfor f in ' + RELEASE_FILES[profile]
               + '; do\n    [ -r "$f" ] || continue\n    echo "--- $f ---"\n    cat "$f"\ndone\n')
    return release + {
        'rpm': RPM_REPOS + RPM, 'suse': SUSE_REPOS + RPM,
        'deb': DEB, 'alpine': APK, 'arch': PACMAN,
    }[profile]


def collector_command(family: str) -> str:
    """Full local inventory; never execute configuration or refresh repositories."""
    profile = collector_profile(family)
    if profile == 'auto':
        body = r'''VA_OS_ID=""
for f in /etc/os-release /usr/lib/os-release; do
    [ -r "$f" ] || continue
    VA_OS_ID=$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print tolower($2); exit }' "$f")
    [ -n "$VA_OS_ID" ] && break
done
case "$VA_OS_ID" in
    sles|sled|opensuse*) VA_PROFILE=suse ;;
    debian|ubuntu|linuxmint|kali) VA_PROFILE=deb ;;
    alpine) VA_PROFILE=alpine ;;
    arch) VA_PROFILE=arch ;;
    rhel|centos|rocky|almalinux|ol|amzn|fedora|euleros|hce|openeuler) VA_PROFILE=rpm ;;
    *)
        if [ -r /var/lib/dpkg/status ]; then VA_PROFILE=deb
        elif [ -r /lib/apk/db/installed ]; then VA_PROFILE=alpine
        elif [ -d /var/lib/pacman/local ]; then VA_PROFILE=arch
        elif [ -r /etc/SuSE-release ]; then VA_PROFILE=suse
        elif command -v rpm >/dev/null 2>&1; then VA_PROFILE=rpm
        else VA_PROFILE=unknown
        fi ;;
esac
case "$VA_PROFILE" in
'''
        for item in ('rpm', 'suse', 'deb', 'alpine', 'arch'):
            body += item + ')\n' + _body(item) + ';;\n'
        body += '*) echo "===== COLLECTOR_WARNINGS ====="\necho "failed: UNSUPPORTED_PACKAGE_MANAGER" ;;\nesac\n'
    else:
        body = _body(profile)
    return (
        '# OfflineVA local collector: ' + LABELS[profile] + '\n'
        '# Read-only. Adapts to old/new OS (sysv/systemd, rpm/dpkg, ss/netstat).\n'
        '# Includes package inventory + container/orchestration platform intelligence.\n'
        + HEADER + body + END
    )
