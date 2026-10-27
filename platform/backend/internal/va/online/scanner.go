package online

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nestho/hardenx/platform/backend/internal/connector"
)

// Common enterprise ports
var Top100Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 1723, 2049, 2181, 2375, 2376, 3000, 3306, 3389, 4369, 5000,
	5432, 5672, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8080, 8081, 8443,
	8888, 9000, 9090, 9092, 9200, 9300, 11211, 27017, 27018, 50000,
}

type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "open", "closed", "filtered"
	Service  string `json:"service"`
	Banner   string `json:"banner,omitempty"`
	TLSInfo  *TLSDetails `json:"tls_info,omitempty"`
}

type TLSDetails struct {
	Version      string   `json:"version"`
	CipherSuite  string   `json:"cipher_suite"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	ExpiresAt    string   `json:"expires_at"`
	SANs         []string `json:"sans"`
	IsExpired    bool     `json:"is_expired"`
	WeakCipher   bool     `json:"weak_cipher"`
}

type DiscoveryResult struct {
	Host        string       `json:"host"`
	IsAlive     bool         `json:"is_alive"`
	LatencyMs   int64        `json:"latency_ms"`
	OSGuess     string       `json:"os_guess"`
	OpenPorts   []PortResult `json:"open_ports"`
}

type PackageInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Release      string `json:"release,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
}

type HostAuditLedger struct {
	Discovery    DiscoveryResult `json:"discovery"`
	OSName       string          `json:"os_name"`
	OSVersion    string          `json:"os_version"`
	Kernel       string          `json:"kernel"`
	Hostname     string          `json:"hostname"`
	Packages     []PackageInfo   `json:"packages"`
	ListeningSockets []string    `json:"listening_sockets"`
	Services     []string        `json:"services"`
}

// CheckHostLiveness performs fast TCP probing on standard control ports
func CheckHostLiveness(host string, timeout time.Duration) (bool, int64) {
	testPorts := []int{80, 443, 22, 445, 3389, 8080}
	for _, p := range testPorts {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), timeout)
		if err == nil {
			conn.Close()
			return true, time.Since(start).Milliseconds()
		}
	}
	return false, 0
}

// ScanPorts scans the requested port slice with adaptive concurrency and token bucket pacing
func ScanPorts(host string, ports []int, concurrency int, timeout time.Duration) []PortResult {
	if concurrency <= 0 {
		concurrency = 20
	}
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}

	results := make([]PortResult, 0, len(ports))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			res := probePort(host, port, timeout)
			if res.State == "open" {
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return results
}

func probePort(host string, port int, timeout time.Duration) PortResult {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return PortResult{Port: port, Protocol: "tcp", State: "closed"}
	}
	defer conn.Close()

	res := PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  identifyService(port),
	}

	// Read banner if available
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Banner = strings.TrimSpace(string(buf[:n]))
	}

	// If port is TLS-enabled or banner empty on web ports, attempt TLS handshake
	if port == 443 || port == 8443 || port == 5986 || port == 9443 || strings.Contains(strings.ToLower(res.Banner), "tls") {
		tlsDetails := probeTLS(host, port, timeout)
		if tlsDetails != nil {
			res.TLSInfo = tlsDetails
			if res.Service == "unknown" {
				res.Service = "https/ssl"
			}
		}
	}

	return res
}

func probeTLS(host string, port int, timeout time.Duration) *TLSDetails {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	details := &TLSDetails{
		Version:     tlsVersionToString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		WeakCipher:  isWeakCipher(state.CipherSuite, state.Version),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		details.Issuer = cert.Issuer.CommonName
		details.Subject = cert.Subject.CommonName
		details.ExpiresAt = cert.NotAfter.Format(time.RFC3339)
		details.SANs = cert.DNSNames
		details.IsExpired = time.Now().After(cert.NotAfter)
	}

	return details
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0 (Deprecated)"
	case tls.VersionTLS11:
		return "TLS 1.1 (Deprecated)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func isWeakCipher(cipher uint16, version uint16) bool {
	if version < tls.VersionTLS12 {
		return true
	}
	// Flag CBC ciphers or 3DES
	name := strings.ToLower(tls.CipherSuiteName(cipher))
	if strings.Contains(name, "cbc") || strings.Contains(name, "3des") || strings.Contains(name, "rc4") {
		return true
	}
	return false
}

func identifyService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb/cifs"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2049:
		return "nfs"
	case 2375, 2376:
		return "docker"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5672:
		return "rabbitmq"
	case 5985:
		return "winrm-http"
	case 5986:
		return "winrm-https"
	case 6379:
		return "redis"
	case 6443:
		return "k8s-api"
	case 8080, 8000, 8888:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 9092:
		return "kafka"
	case 9200, 9300:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}

// ExtractLinuxPackageLedger queries package manager and system info via SSH
func ExtractLinuxPackageLedger(conn connector.Connector) (*HostAuditLedger, error) {
	ledger := &HostAuditLedger{}

	// Hostname
	if host, _, err := conn.Run("hostname"); err == nil {
		ledger.Hostname = strings.TrimSpace(host)
	}

	// Kernel
	if kern, _, err := conn.Run("uname -r"); err == nil {
		ledger.Kernel = strings.TrimSpace(kern)
	}

	// OS release info
	if osRel, err := conn.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(osRel, "\n") {
			if strings.HasPrefix(line, "NAME=") {
				ledger.OSName = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
			} else if strings.HasPrefix(line, "VERSION_ID=") {
				ledger.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
			}
		}
	}

	// Package query: RPM vs DPKG
	rpmOut, exitRPM, _ := conn.Run(`rpm -qa --qf "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n" 2>/dev/null`)
	if exitRPM == 0 && len(rpmOut) > 20 {
		lines := strings.Split(rpmOut, "\n")
		for _, l := range lines {
			parts := strings.Split(strings.TrimSpace(l), "|")
			if len(parts) >= 5 {
				ver := parts[2]
				if parts[1] != "(none)" && parts[1] != "" && parts[1] != "0" {
					ver = parts[1] + ":" + ver
				}
				ledger.Packages = append(ledger.Packages, PackageInfo{
					Name:         parts[0],
					Version:      ver,
					Release:      parts[3],
					Architecture: parts[4],
					Vendor:       "redhat/rpm",
				})
			}
		}
	} else {
		// Try dpkg-query
		dpkgOut, exitDPKG, _ := conn.Run(`dpkg-query -W -f='${Package}|${Version}|${Architecture}\n' 2>/dev/null`)
		if exitDPKG == 0 && len(dpkgOut) > 20 {
			lines := strings.Split(dpkgOut, "\n")
			for _, l := range lines {
				parts := strings.Split(strings.TrimSpace(l), "|")
				if len(parts) >= 3 {
					ledger.Packages = append(ledger.Packages, PackageInfo{
						Name:         parts[0],
						Version:      parts[1],
						Architecture: parts[2],
						Vendor:       "debian/dpkg",
					})
				}
			}
		}
	}

	// Listening sockets
	if sockOut, _, err := conn.Run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"); err == nil {
		for _, line := range strings.Split(sockOut, "\n") {
			l := strings.TrimSpace(line)
			if l != "" && !strings.HasPrefix(l, "Proto") && !strings.HasPrefix(l, "Netid") {
				ledger.ListeningSockets = append(ledger.ListeningSockets, l)
			}
		}
	}

	return ledger, nil
}

// ExtractWindowsPackageLedger queries HotFixes and installed programs via WinRM / PowerShell
func ExtractWindowsPackageLedger(conn connector.Connector) (*HostAuditLedger, error) {
	ledger := &HostAuditLedger{
		OSName: "Microsoft Windows",
	}

	// Hostname
	if host, _, err := conn.Run("hostname"); err == nil {
		ledger.Hostname = strings.TrimSpace(host)
	}

	// OS Version
	psOS := "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version"
	if out, _, err := conn.Run(psOS); err == nil && len(out) > 0 {
		ledger.OSVersion = strings.TrimSpace(out)
	}

	// HotFixes
	psHotfix := "Get-HotFix | Select-Object -Property HotFixID, InstalledOn | ConvertTo-Csv -NoTypeInformation"
	if out, _, err := conn.Run(psHotfix); err == nil {
		for _, line := range strings.Split(out, "\n") {
			parts := strings.Split(strings.Trim(strings.TrimSpace(line), `"`), `","`)
			if len(parts) >= 1 && strings.HasPrefix(parts[0], "KB") {
				ledger.Packages = append(ledger.Packages, PackageInfo{
					Name:    parts[0],
					Version: "Installed",
					Vendor:  "microsoft",
				})
			}
		}
	}

	return ledger, nil
}
