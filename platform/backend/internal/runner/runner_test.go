package runner

import (
	"context"
	"testing"

	"github.com/nestho/cisbenchmarks/platform/backend/internal/audit"
)

type mockConnector struct {
	runOut  string
	runExit int
	fileOut string
}

func (m *mockConnector) Run(cmd string) (string, int, error) {
	return m.runOut, m.runExit, nil
}

func (m *mockConnector) ReadFile(path string) (string, error) {
	return m.fileOut, nil
}

func (m *mockConnector) Close() {}

func TestRunnerCommandPass(t *testing.T) {
	mock := &mockConnector{runOut: "auditd is active\n", runExit: 0}
	rn := New(mock)

	bm := &audit.Benchmark{
		ID:    "test-bm",
		Title: "Test Benchmark",
		Controls: []audit.Control{
			{
				ID:    "1.1",
				Title: "Ensure auditd is running",
				Checks: []audit.Check{
					{
						Type:     "command",
						Command:  "systemctl is-active auditd",
						Expected: "active",
					},
				},
			},
		},
	}

	results := rn.Run(context.Background(), bm)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "pass" {
		t.Errorf("expected pass, got %s", results[0].Status)
	}
}

func TestRunnerRegistryPass(t *testing.T) {
	mock := &mockConnector{runOut: "1"}
	rn := New(mock)

	bm := &audit.Benchmark{
		ID:    "win-bm",
		Title: "Windows Benchmark",
		Controls: []audit.Control{
			{
				ID:    "1.2",
				Title: "Ensure Undock Without Logon is disabled",
				Checks: []audit.Check{
					{
						Type:      "registry",
						RegKey:    `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System`,
						RegItem:   "UndockWithoutLogon",
						ValueData: "1",
					},
				},
			},
		},
	}

	results := rn.Run(context.Background(), bm)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "pass" {
		t.Errorf("expected pass, got %s", results[0].Status)
	}
}
