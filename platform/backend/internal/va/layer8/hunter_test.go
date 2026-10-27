package layer8

import (
	"strings"
	"testing"
)

type mockConnector struct {
	commands map[string]string
	files    map[string]string
}

func (m *mockConnector) Run(cmd string) (string, int, error) {
	for k, v := range m.commands {
		if strings.Contains(cmd, k) {
			return v, 0, nil
		}
	}
	return "", 0, nil
}

func (m *mockConnector) ReadFile(path string) (string, error) {
	if val, ok := m.files[path]; ok {
		return val, nil
	}
	return "", nil
}

func (m *mockConnector) Close() {}

func TestAuditLinuxHostAnomalies(t *testing.T) {
	mock := &mockConnector{
		commands: map[string]string{
			"exe":         "lrwxrwxrwx 1 root root 0 Oct 27 10:00 /proc/1337/exe -> /dev/shm/payload (deleted)",
			"maps":        "00400000-00401000 rwxp 00000000 00:00 0",
			"HIDDEN_PID:": "HIDDEN_PID:9999",
		},
		files: map[string]string{
			"/etc/ld.so.preload":      "/usr/local/lib/libhook.so",
			"/proc/sys/kernel/tainted": "4097", // bit 0 + bit 12
		},
	}

	rep := AuditLinuxHost(mock, "192.168.1.50")
	if rep.AnomaliesFound == 0 {
		t.Fatalf("expected anomalies to be found, got 0")
	}

	if rep.HighestSeverity != SeverityCritical {
		t.Errorf("expected highest severity CRITICAL, got %s", rep.HighestSeverity)
	}

	var hasDeleted, hasPreload, hasTainted bool
	for _, f := range rep.Findings {
		if f.ID == "L8-LIN-001" {
			hasDeleted = true
		}
		if f.ID == "L8-LIN-003" {
			hasPreload = true
		}
		if f.ID == "L8-LIN-004" {
			hasTainted = true
		}
	}

	if !hasDeleted {
		t.Errorf("missing L8-LIN-001 (unlinked executable)")
	}
	if !hasPreload {
		t.Errorf("missing L8-LIN-003 (ld.so.preload)")
	}
	if !hasTainted {
		t.Errorf("missing L8-LIN-004 (tainted kernel)")
	}
}

func TestAuditWindowsHostAnomalies(t *testing.T) {
	mock := &mockConnector{
		commands: map[string]string{
			"ParentProcessId": `{"ProcessId": 4040, "ParentProcessId": 4, "Name": "powershell.exe"}`,
			"pipe":            `["\\\\.\\pipe\\msagent_01", "\\\\.\\pipe\\protected_storage"]`,
			"SystemDriver":    `[{"Name": "gdrv", "PathName": "C:\\Windows\\System32\\drivers\\gdrv.sys"}]`,
		},
	}

	rep := AuditWindowsHost(mock, "192.168.1.100")
	if rep.AnomaliesFound == 0 {
		t.Fatalf("expected Windows anomalies, got 0")
	}

	var hasPPID, hasPipe, hasBYOVD bool
	for _, f := range rep.Findings {
		if f.ID == "L8-WIN-001" {
			hasPPID = true
		}
		if f.ID == "L8-WIN-002" {
			hasPipe = true
		}
		if f.ID == "L8-WIN-003" {
			hasBYOVD = true
		}
	}

	if !hasPPID {
		t.Errorf("missing L8-WIN-001 (PPID anomaly)")
	}
	if !hasPipe {
		t.Errorf("missing L8-WIN-002 (C2 named pipe)")
	}
	if !hasBYOVD {
		t.Errorf("missing L8-WIN-003 (vulnerable BYOVD driver)")
	}
}
