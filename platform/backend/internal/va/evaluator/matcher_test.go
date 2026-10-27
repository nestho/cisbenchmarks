package evaluator

import (
	"testing"

	"github.com/nestho/hardenx/platform/backend/internal/va/online"
)

func TestEvaluatePackagesBackportElimination(t *testing.T) {
	// OpenSSH 8.7p1-38.el9_4.1 contains the backport fix for CVE-2024-6387 (regreSSHion)
	// It should NOT be flagged as vulnerable (Zero False Positive)
	packages := []online.PackageInfo{
		{
			Name:    "openssh-server",
			Version: "8.7p1",
			Release: "38.el9_4.1",
			Vendor:  "redhat/rpm",
		},
		{
			Name:    "sudo",
			Version: "1.8.23",
			Release: "1.el8", // Vulnerable to CVE-2021-3156 (Baron Samedit)
			Vendor:  "redhat/rpm",
		},
	}

	rep := EvaluatePackages(packages)

	if rep.BackportsEliminated == 0 {
		t.Errorf("expected at least 1 backport fix to be eliminated, got %d", rep.BackportsEliminated)
	}

	var foundSudo bool
	for _, v := range rep.Vulnerabilities {
		if v.CVEID == "CVE-2024-6387" {
			t.Errorf("false positive: CVE-2024-6387 should have been eliminated by backport verification")
		}
		if v.CVEID == "CVE-2021-3156" {
			foundSudo = true
			if !v.IsKEV {
				t.Errorf("expected CVE-2021-3156 to be flagged as CISA KEV")
			}
		}
	}

	if !foundSudo {
		t.Errorf("expected sudo CVE-2021-3156 to be detected")
	}
}
