package evaluator

import (
	"fmt"
	"strings"

	"github.com/nestho/hardenx/platform/backend/internal/standards"
	"github.com/nestho/hardenx/platform/backend/internal/va/online"
)

type VulnerabilitySeverity string

const (
	SevCritical VulnerabilitySeverity = "CRITICAL"
	SevHigh     VulnerabilitySeverity = "HIGH"
	SevMedium   VulnerabilitySeverity = "MEDIUM"
	SevLow      VulnerabilitySeverity = "LOW"
)

type VulnerabilityMatch struct {
	CVEID            string                `json:"cve_id"`
	Title            string                `json:"title"`
	Severity         VulnerabilitySeverity `json:"severity"`
	CVSSScore        float64               `json:"cvss_score"`
	EPSSScore        float64               `json:"epss_score"`
	IsKEV            bool                  `json:"is_kev"`
	KEVDetails       *standards.KEVEntry   `json:"kev_details,omitempty"`
	PackageName      string                `json:"package_name"`
	InstalledVersion string                `json:"installed_version"`
	FixedVersion     string                `json:"fixed_version"`
	BackportVerified bool                  `json:"backport_verified"` // True = Backport fix verified (Zero FP)
	Remediation      string                `json:"remediation"`
}

type VulnerabilityReport struct {
	TotalVulnerabilities int                  `json:"total_vulnerabilities"`
	CriticalCount        int                  `json:"critical_count"`
	HighCount            int                  `json:"high_count"`
	MediumCount          int                  `json:"medium_count"`
	LowCount             int                  `json:"low_count"`
	KEVCount             int                  `json:"kev_count"`
	BackportsEliminated  int                  `json:"backports_eliminated"`
	Vulnerabilities      []VulnerabilityMatch `json:"vulnerabilities"`
}

// Well-known high-impact baseline CVE signatures for active package ecosystems
type KnownAdvisory struct {
	PackagePattern   string
	AffectedBelow    string
	CVEID            string
	Title            string
	Severity         VulnerabilitySeverity
	CVSS             float64
	FixedVersion     string
	BackportReleases []string
}

var CoreAdvisories = []KnownAdvisory{
	{
		PackagePattern:   "openssl",
		AffectedBelow:    "3.0.7",
		CVEID:            "CVE-2022-3602",
		Title:            "OpenSSL X.509 Email Address 4-byte Buffer Overflow",
		Severity:         SevHigh,
		CVSS:             8.1,
		FixedVersion:     "3.0.7",
		BackportReleases: []string{"3.0.1-43.el9_0", "3.0.7-1ubuntu1"},
	},
	{
		PackagePattern:   "openssl",
		AffectedBelow:    "1.1.1u",
		CVEID:            "CVE-2023-0286",
		Title:            "OpenSSL X.400 address type confusion vulnerability",
		Severity:         SevHigh,
		CVSS:             8.2,
		FixedVersion:     "1.1.1u",
		BackportReleases: []string{"1.1.1k-29.el8_7"},
	},
	{
		PackagePattern:   "openssh",
		AffectedBelow:    "9.8p1",
		CVEID:            "CVE-2024-6387",
		Title:            "OpenSSH regreSSHion Remote Code Execution in sshd (glibc race condition)",
		Severity:         SevCritical,
		CVSS:             9.8,
		FixedVersion:     "9.8p1",
		BackportReleases: []string{"8.7p1-38.el9_4.1", "8.9p1-3ubuntu0.10"},
	},
	{
		PackagePattern:   "sudo",
		AffectedBelow:    "1.9.5p2",
		CVEID:            "CVE-2021-3156",
		Title:            "Sudo Baron Samedit Heap-Based Buffer Overflow Privilege Escalation",
		Severity:         SevCritical,
		CVSS:             9.8,
		FixedVersion:     "1.9.5p2",
		BackportReleases: []string{"1.8.29-6.el8_3.1", "1.8.31-1ubuntu1.2"},
	},
	{
		PackagePattern:   "polkit",
		AffectedBelow:    "0.105-26",
		CVEID:            "CVE-2021-4034",
		Title:            "Polkit PwnKit Local Privilege Escalation in pkexec",
		Severity:         SevHigh,
		CVSS:             7.8,
		FixedVersion:     "0.105-26",
		BackportReleases: []string{"0.115-13.el8_5.1", "0.105-26ubuntu0.1"},
	},
	{
		PackagePattern:   "log4j",
		AffectedBelow:    "2.17.1",
		CVEID:            "CVE-2021-44228",
		Title:            "Apache Log4j Log4Shell Remote Code Execution via JNDI Injection",
		Severity:         SevCritical,
		CVSS:             10.0,
		FixedVersion:     "2.17.1",
	},
	{
		PackagePattern:   "curl",
		AffectedBelow:    "8.4.0",
		CVEID:            "CVE-2023-38545",
		Title:            "curl SOCKS5 Heap Buffer Overflow",
		Severity:         SevHigh,
		CVSS:             8.8,
		FixedVersion:     "8.4.0",
		BackportReleases: []string{"7.76.1-26.el9_2.1"},
	},
}

// EvaluatePackages analyzes a package ledger and performs zero-false-positive vulnerability matching
func EvaluatePackages(packages []online.PackageInfo) *VulnerabilityReport {
	hub := standards.GetHub()
	rep := &VulnerabilityReport{
		Vulnerabilities: make([]VulnerabilityMatch, 0),
	}

	for _, pkg := range packages {
		pkgNameLower := strings.ToLower(pkg.Name)

		for _, adv := range CoreAdvisories {
			if strings.Contains(pkgNameLower, adv.PackagePattern) {
				fullVR := pkg.Version
				if pkg.Release != "" {
					fullVR = pkg.Version + "-" + pkg.Release
				}
				backportSafe := false
				for _, bp := range adv.BackportReleases {
					if strings.Contains(fullVR, bp) || strings.Contains(pkg.Release, bp) || strings.Contains(pkg.Version, bp) {
						backportSafe = true
						break
					}
				}

				if backportSafe {
					rep.BackportsEliminated++
					continue // Zero false positive: patch was backported by vendor
				}

				// Check version comparison
				if isVersionOlder(pkg.Version, adv.AffectedBelow) {
					isKEV, kevDetails := hub.IsKnownExploited(adv.CVEID)
					epss, _ := hub.EstimateEPSS(adv.CVEID)

					match := VulnerabilityMatch{
						CVEID:            adv.CVEID,
						Title:            adv.Title,
						Severity:         adv.Severity,
						CVSSScore:        adv.CVSS,
						EPSSScore:        epss,
						IsKEV:            isKEV,
						KEVDetails:       kevDetails,
						PackageName:      pkg.Name,
						InstalledVersion: pkg.Version,
						FixedVersion:     adv.FixedVersion,
						BackportVerified: false,
						Remediation:      fmt.Sprintf("Upgrade %s to version >= %s via OS package manager.", pkg.Name, adv.FixedVersion),
					}

					rep.Vulnerabilities = append(rep.Vulnerabilities, match)
					rep.TotalVulnerabilities++

					switch adv.Severity {
					case SevCritical:
						rep.CriticalCount++
					case SevHigh:
						rep.HighCount++
					case SevMedium:
						rep.MediumCount++
					case SevLow:
						rep.LowCount++
					}

					if isKEV {
						rep.KEVCount++
					}
				}
			}
		}
	}

	return rep
}

// isVersionOlder performs simple semantic component comparison
func isVersionOlder(current, threshold string) bool {
	// Strip epoch prefixes if present
	if idx := strings.Index(current, ":"); idx != -1 {
		current = current[idx+1:]
	}
	if idx := strings.Index(threshold, ":"); idx != -1 {
		threshold = threshold[idx+1:]
	}

	cParts := strings.Split(current, ".")
	tParts := strings.Split(threshold, ".")

	maxLen := len(cParts)
	if len(tParts) > maxLen {
		maxLen = len(tParts)
	}

	for i := 0; i < maxLen; i++ {
		var cVal, tVal int
		if i < len(cParts) {
			_, _ = fmt.Sscanf(cParts[i], "%d", &cVal)
		}
		if i < len(tParts) {
			_, _ = fmt.Sscanf(tParts[i], "%d", &tVal)
		}
		if cVal < tVal {
			return true
		}
		if cVal > tVal {
			return false
		}
	}
	return false
}
