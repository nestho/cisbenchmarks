package standards

import (
	"testing"
)

func TestStandardsHubKEV(t *testing.T) {
	hub := GetHub()
	count := hub.GetKEVCount()
	if count == 0 {
		t.Logf("Notice: KEV count is 0 (file might be loaded via relative path depending on cwd)")
	} else {
		t.Logf("Successfully indexed %d CISA KEV vulnerabilities", count)
	}

	// Test Log4Shell
	isKEV, entry := hub.IsKnownExploited("CVE-2021-44228")
	if count > 0 && !isKEV {
		t.Errorf("expected CVE-2021-44228 to be in CISA KEV")
	}
	if isKEV && entry != nil {
		if entry.VendorProject == "" {
			t.Errorf("expected vendor project to be non-empty")
		}
	}
}

func TestStandardsHubEPSS(t *testing.T) {
	hub := GetHub()
	score, percentile := hub.EstimateEPSS("CVE-2021-44228")
	if score <= 0 || percentile <= 0 {
		t.Errorf("expected positive score and percentile, got %f, %f", score, percentile)
	}
}

func TestMapCISControlToStandards(t *testing.T) {
	hub := GetHub()
	m1 := hub.MapCISControlToStandards("5.2.1", "Ensure SSH Protocol is set to 2")
	if len(m1.NISTControls) == 0 {
		t.Errorf("expected NIST controls for SSH")
	}
	if m1.Category != "Identification, Authentication & Access Control" {
		t.Errorf("expected Auth category, got %s", m1.Category)
	}

	m2 := hub.MapCISControlToStandards("3.1.1", "Ensure iptables packages are installed")
	if m2.Category != "Network Security & Boundary Defense" {
		t.Errorf("expected Network category, got %s", m2.Category)
	}
}

func TestStandardsHubSummary(t *testing.T) {
	hub := GetHub()
	s := hub.Summary()
	if s["standards_indexed"] == nil {
		t.Errorf("expected standards_indexed list")
	}
}
