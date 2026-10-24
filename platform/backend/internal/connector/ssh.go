package connector

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyPath  string
	Timeout  time.Duration
}

type SSH struct {
	cfg    SSHConfig
	client *ssh.Client
}

func NewSSH(cfg SSHConfig) (*SSH, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	auth := []ssh.AuthMethod{}
	if cfg.KeyPath != "" {
		key, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
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
		return nil, err
	}
	return &SSH{cfg: cfg, client: client}, nil
}

func (s *SSH) Run(cmd string) (string, int, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer session.Close()
	var out strings.Builder
	session.Stdout = &out
	session.Stderr = &out
	err = session.Run(cmd)
	exit := 0
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exit = exitErr.ExitStatus()
		} else {
			return out.String(), -1, err
		}
	}
	return out.String(), exit, nil
}

func (s *SSH) ReadFile(path string) (string, error) {
	out, exit, err := s.Run("cat " + shellQuote(path))
	if err != nil {
		return "", err
	}
	if exit != 0 {
		return "", fmt.Errorf("read file failed: %s", out)
	}
	return out, nil
}

func (s *SSH) Close() {
	if s.client != nil {
		s.client.Close()
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// helper to read lines
func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}
