package connector

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DeviceType represents the target network appliance operating system.
type DeviceType string

const (
	DeviceCiscoIOS  DeviceType = "cisco_ios"
	DeviceCiscoNXOS DeviceType = "cisco_nxos"
	DeviceFortiOS   DeviceType = "fortios"
	DevicePanOS     DeviceType = "panos"
	DeviceJunOS     DeviceType = "junos"
	DeviceGeneric   DeviceType = "generic"
)

// NetworkSSHConfig holds connection and execution parameters for network devices.
type NetworkSSHConfig struct {
	Host        string
	Port        int
	User        string
	Password    string
	KeyPath     string
	DeviceType  DeviceType
	Pacing      time.Duration // Delay between commands to prevent control plane overload
	Timeout     time.Duration
	PromptRegex string
}

// NetworkSSH maintains a single, persistent, serial interactive session with an appliance.
// It eliminates session exhaustion, account lockouts, and appliance control plane spikes.
type NetworkSSH struct {
	cfg     NetworkSSHConfig
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	prompt  *regexp.Regexp
	mu      sync.Mutex
}

// NewNetworkSSH establishes a single persistent session and disables terminal paging.
func NewNetworkSSH(cfg NetworkSSHConfig) (*NetworkSSH, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Pacing == 0 {
		cfg.Pacing = 60 * time.Millisecond // Gentle default pacing
	}
	if cfg.DeviceType == "" {
		cfg.DeviceType = DeviceGeneric
	}

	auth := []ssh.AuthMethod{}
	if cfg.KeyPath != "" {
		key, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		auth = append(auth, ssh.Password(cfg.Password))
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial network device %s:%d: %w", cfg.Host, cfg.Port, err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("new ssh session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echo
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := session.RequestPty("vt100", 0, 0, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	promptPattern := cfg.PromptRegex
	if promptPattern == "" {
		// Generic appliance prompt ending with #, >, $, or %
		promptPattern = `(?m)[\w\.\-\(\)]+[#>$%]\s*$`
	}
	promptRe, err := regexp.Compile(promptPattern)
	if err != nil {
		promptRe = regexp.MustCompile(`(?m)[#>$%]\s*$`)
	}

	n := &NetworkSSH{
		cfg:     cfg,
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		prompt:  promptRe,
	}

	// Drain initial banner / greeting up to the first prompt
	_, _ = n.readUntilPrompt(5 * time.Second)

	// Disable terminal pager per device type to avoid hanging on "--More--"
	if err := n.disablePager(); err != nil {
		n.Close()
		return nil, fmt.Errorf("disable pager: %w", err)
	}

	return n, nil
}

// disablePager sends platform-specific terminal pager bypass commands.
func (n *NetworkSSH) disablePager() error {
	var cmds []string
	switch n.cfg.DeviceType {
	case DeviceCiscoIOS, DeviceCiscoNXOS:
		cmds = []string{"terminal length 0", "terminal width 512"}
	case DeviceFortiOS:
		cmds = []string{"config system console", "set output standard", "end"}
	case DevicePanOS:
		cmds = []string{"set cli pager off"}
	case DeviceJunOS:
		cmds = []string{"set cli screen-length 0"}
	default:
		// Attempt standard Cisco command as best-effort
		cmds = []string{"terminal length 0"}
	}

	for _, cmd := range cmds {
		_, _, err := n.runInternal(cmd, 5*time.Second)
		if err != nil {
			// Do not hard fail on generic fallback pager commands
			continue
		}
	}
	return nil
}

// Run executes a command serially on the persistent appliance session.
func (n *NetworkSSH) Run(cmd string) (string, int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Inter-command pacing to prevent CPU / rate-limit spikes on appliances
	if n.cfg.Pacing > 0 {
		time.Sleep(n.cfg.Pacing)
	}

	timeout := n.cfg.Timeout
	if timeout == 0 {
		timeout = 25 * time.Second
	}

	return n.runInternal(cmd, timeout)
}

func (n *NetworkSSH) runInternal(cmd string, timeout time.Duration) (string, int, error) {
	cmdTrim := strings.TrimSpace(cmd) + "\n"
	if _, err := io.WriteString(n.stdin, cmdTrim); err != nil {
		return "", -1, fmt.Errorf("write command to stdin: %w", err)
	}

	rawOutput, err := n.readUntilPrompt(timeout)
	if err != nil {
		return rawOutput, -1, err
	}

	// Clean output: strip echo of command and trailing prompt
	lines := strings.Split(rawOutput, "\n")
	cleaned := make([]string, 0, len(lines))
	for idx, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		// Skip first line if it's the echoed command
		if idx == 0 && strings.Contains(trimmed, strings.TrimSpace(cmd)) {
			continue
		}
		// Skip trailing prompt line
		if idx == len(lines)-1 && n.prompt.MatchString(trimmed) {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}

	output := strings.Join(cleaned, "\n")
	return strings.TrimSpace(output), 0, nil
}

// readUntilPrompt reads chunks from stdout until prompt regex matches or timeout triggers.
func (n *NetworkSSH) readUntilPrompt(timeout time.Duration) (string, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 1024)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		readDone := make(chan struct {
			n   int
			err error
		}, 1)

		go func() {
			numRead, err := n.stdout.Read(chunk)
			readDone <- struct {
				n   int
				err error
			}{numRead, err}
		}()

		select {
		case res := <-readDone:
			if res.n > 0 {
				buf.Write(chunk[:res.n])
				current := buf.String()
				if n.prompt.MatchString(current) {
					return current, nil
				}
			}
			if res.err != nil {
				if res.err == io.EOF {
					return buf.String(), nil
				}
				return buf.String(), res.err
			}
		case <-time.After(500 * time.Millisecond):
			// Check if prompt arrived during brief buffer delay
			if n.prompt.MatchString(buf.String()) {
				return buf.String(), nil
			}
		}
	}

	return buf.String(), fmt.Errorf("timeout waiting for prompt (%v)", timeout)
}

// ReadFile runs show running-config or equivalent configuration dump.
func (n *NetworkSSH) ReadFile(path string) (string, error) {
	var cmd string
	switch n.cfg.DeviceType {
	case DevicePanOS:
		cmd = "show config running"
	case DeviceFortiOS:
		cmd = "show full-configuration"
	case DeviceJunOS:
		cmd = "show configuration"
	default:
		cmd = fmt.Sprintf("show running-config %s", path)
	}

	out, exit, err := n.Run(cmd)
	if err != nil || exit != 0 {
		return "", fmt.Errorf("read appliance config failed (exit %d): %w", exit, err)
	}
	return out, nil
}

// Close gracefully closes the persistent session and underlying SSH client.
func (n *NetworkSSH) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stdin != nil {
		_, _ = io.WriteString(n.stdin, "exit\n")
		_ = n.stdin.Close()
	}
	if n.session != nil {
		_ = n.session.Close()
	}
	if n.client != nil {
		_ = n.client.Close()
	}
}
