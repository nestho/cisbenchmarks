package connector

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

type WinRMConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	HTTPS    bool
	Insecure bool
	Timeout  time.Duration
}

type WinRM struct {
	cfg    WinRMConfig
	client *winrm.Client
}

func NewWinRM(cfg WinRMConfig) (*WinRM, error) {
	if cfg.Port == 0 {
		if cfg.HTTPS {
			cfg.Port = 5986
		} else {
			cfg.Port = 5985
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 45 * time.Second
	}

	endpoint := winrm.NewEndpoint(
		cfg.Host,
		cfg.Port,
		cfg.HTTPS,
		cfg.Insecure,
		nil,
		nil,
		nil,
		cfg.Timeout,
	)

	client, err := winrm.NewClient(endpoint, cfg.User, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("winrm client init failed: %w", err)
	}

	return &WinRM{
		cfg:    cfg,
		client: client,
	}, nil
}

// Run executes a raw command via cmd.exe on remote Windows host
func (w *WinRM) Run(cmd string) (string, int, error) {
	var stdout, stderr bytes.Buffer
	exitCode, err := w.client.Run(cmd, &stdout, &stderr)
	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += stderr.String()
	}
	return output, exitCode, err
}

// RunPS executes a command or script using PowerShell
func (w *WinRM) RunPS(psScript string) (string, int, error) {
	var stdout, stderr bytes.Buffer
	exitCode, err := w.client.Run(winrm.Powershell(psScript), &stdout, &stderr)
	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += stderr.String()
	}
	return output, exitCode, err
}

// ReadFile retrieves the content of a remote file via PowerShell Get-Content
func (w *WinRM) ReadFile(path string) (string, error) {
	sanitized := strings.ReplaceAll(path, "'", "''")
	cmd := fmt.Sprintf("Get-Content -LiteralPath '%s' -Raw -ErrorAction Stop", sanitized)
	out, exitCode, err := w.RunPS(cmd)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("failed to read file '%s': exit %d, %s", path, exitCode, strings.TrimSpace(out))
	}
	return out, nil
}

// ReadRegistry reads a registry value from remote Windows registry
func (w *WinRM) ReadRegistry(keyPath, valueName string) (string, error) {
	sanitizedKey := strings.ReplaceAll(keyPath, "'", "''")
	sanitizedVal := strings.ReplaceAll(valueName, "'", "''")
	cmd := fmt.Sprintf("(Get-ItemProperty -LiteralPath '%s' -Name '%s' -ErrorAction Stop).'%s'", sanitizedKey, sanitizedVal, sanitizedVal)
	out, exitCode, err := w.RunPS(cmd)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("failed to read registry '%s\\%s': %s", keyPath, valueName, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

func (w *WinRM) Close() {
	// WinRM uses stateless HTTP/HTTPS calls; no persistent connection pool teardown needed
}
