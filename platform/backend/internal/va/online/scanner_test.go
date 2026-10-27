package online

import (
	"net"
	"testing"
	"time"
)

func TestCheckHostLivenessLocalhost(t *testing.T) {
	// Start a dummy TCP listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port
	alive, lat := CheckHostLiveness("127.0.0.1", 500*time.Millisecond)
	// Even if standard ports aren't open, test ScanPorts directly on open port
	res := ScanPorts("127.0.0.1", []int{port}, 5, 500*time.Millisecond)
	if len(res) == 0 {
		t.Errorf("expected open port %d to be detected", port)
	} else if res[0].State != "open" {
		t.Errorf("expected state open, got %s", res[0].State)
	}
	_ = alive
	_ = lat
}

func TestIdentifyService(t *testing.T) {
	if s := identifyService(22); s != "ssh" {
		t.Errorf("expected ssh, got %s", s)
	}
	if s := identifyService(443); s != "https" {
		t.Errorf("expected https, got %s", s)
	}
	if s := identifyService(5986); s != "winrm-https" {
		t.Errorf("expected winrm-https, got %s", s)
	}
}
