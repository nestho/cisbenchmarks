package remediation

import (
	"strings"
	"testing"

	"github.com/nestho/hardenx/platform/backend/internal/audit"
	"github.com/nestho/hardenx/platform/backend/internal/runner"
	"github.com/nestho/hardenx/platform/backend/internal/scans"
)

func TestGenerateRemediation(t *testing.T) {
	bm := &audit.Benchmark{
		ID:      "test-bm",
		Title:   "Test Benchmark",
		Version: "1.0.0",
		Controls: []audit.Control{
			{
				ID:          "1.1.1",
				Title:       "Ensure test service is disabled",
				Remediation: "Run the following command:\nsudo systemctl disable test-service\nsudo systemctl stop test-service",
			},
			{
				ID:          "1.1.2",
				Title:       "Ensure permissions on file",
				Remediation: "chmod 600 /etc/test.conf\nchown root:root /etc/test.conf",
			},
		},
	}

	job := &scans.Job{
		ID:          "scan-123",
		BenchmarkID: "test-bm",
		Results: []runner.Result{
			{
				ControlID: "1.1.1",
				Status:    "failed",
			},
			{
				ControlID: "1.1.2",
				Status:    "passed",
			},
		},
	}

	// 1. Ansible
	ansible := GenerateAnsiblePlaybook(job, bm)
	if !strings.Contains(ansible, "sudo systemctl disable test-service") {
		t.Fatalf("expected failed control 1.1.1 in Ansible playbook, got:\n%s", ansible)
	}
	if strings.Contains(ansible, "chmod 600 /etc/test.conf") {
		t.Fatalf("passed control 1.1.2 should not be in remediation playbook, got:\n%s", ansible)
	}

	// 2. Bash
	bash := GenerateBashScript(job, bm)
	if !strings.Contains(bash, "sudo systemctl stop test-service") {
		t.Fatalf("expected command in bash script, got:\n%s", bash)
	}

	// 3. PowerShell
	ps := GeneratePowerShellScript(job, bm)
	if !strings.Contains(ps, "1.1.1") {
		t.Fatalf("expected control 1.1.1 in PowerShell script, got:\n%s", ps)
	}
}
