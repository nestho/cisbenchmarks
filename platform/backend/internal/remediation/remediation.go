package remediation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nestho/hardenx/platform/backend/internal/audit"
	"github.com/nestho/hardenx/platform/backend/internal/scans"
)

// ExtractCommands extracts shell or powershell command blocks from remediation text.
func ExtractCommands(raw string) []string {
	var cmds []string
	lines := strings.Split(raw, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		// Strip common shell prompt prefixes
		trimmed = regexp.MustCompile(`^[$#]\s+`).ReplaceAllString(trimmed, "")

		// Heuristic: identify actionable commands
		if strings.HasPrefix(trimmed, "sudo ") ||
			strings.HasPrefix(trimmed, "systemctl ") ||
			strings.HasPrefix(trimmed, "chmod ") ||
			strings.HasPrefix(trimmed, "chown ") ||
			strings.HasPrefix(trimmed, "usermod ") ||
			strings.HasPrefix(trimmed, "useradd ") ||
			strings.HasPrefix(trimmed, "groupadd ") ||
			strings.HasPrefix(trimmed, "apt-get ") ||
			strings.HasPrefix(trimmed, "yum ") ||
			strings.HasPrefix(trimmed, "dnf ") ||
			strings.HasPrefix(trimmed, "echo ") ||
			strings.HasPrefix(trimmed, "sed ") ||
			strings.HasPrefix(trimmed, "Set-ItemProperty") ||
			strings.HasPrefix(trimmed, "New-ItemProperty") ||
			strings.HasPrefix(trimmed, "reg add") ||
			strings.HasPrefix(trimmed, "auditctl ") {
			cmds = append(cmds, trimmed)
		}
	}
	return cmds
}

// GenerateAnsiblePlaybook creates a production-grade YAML Ansible playbook for failed controls.
func GenerateAnsiblePlaybook(job *scans.Job, bm *audit.Benchmark) string {
	failedControlIDs := make(map[string]bool)
	if job != nil {
		for _, res := range job.Results {
			if res.Status == "failed" {
				failedControlIDs[res.ControlID] = true
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("# HardenX Auto-Generated Remediation Playbook\n"))
	if bm != nil {
		sb.WriteString(fmt.Sprintf("# Benchmark: %s (v%s)\n", bm.Title, bm.Version))
	}
	if job != nil {
		sb.WriteString(fmt.Sprintf("# Scan Job: %s\n", job.ID))
	}
	sb.WriteString("- name: HardenX Automated Compliance Remediation\n")
	sb.WriteString("  hosts: all\n")
	sb.WriteString("  become: yes\n")
	sb.WriteString("  tasks:\n")

	count := 0
	if bm != nil {
		for _, ctrl := range bm.Controls {
			// If scan job exists, only remediate failed controls
			if len(failedControlIDs) > 0 && !failedControlIDs[ctrl.ID] {
				continue
			}

			cmds := ExtractCommands(ctrl.Remediation)
			sb.WriteString(fmt.Sprintf("    - name: \"[%s] %s\"\n", ctrl.ID, strings.ReplaceAll(ctrl.Title, "\"", "\\\"")))

			if len(cmds) > 0 {
				sb.WriteString("      ansible.builtin.shell: |\n")
				for _, cmd := range cmds {
					sb.WriteString(fmt.Sprintf("        %s\n", cmd))
				}
			} else {
				// Provide documented manual/configuration step task
				sb.WriteString("      ansible.builtin.debug:\n")
				sb.WriteString(fmt.Sprintf("        msg: \"Manual Remediation Required: %s\"\n", escapeSingleLine(ctrl.Remediation)))
			}
			sb.WriteString("      ignore_errors: yes\n")
			sb.WriteString("      tags:\n")
			sb.WriteString(fmt.Sprintf("        - cis_%s\n", strings.ReplaceAll(ctrl.ID, ".", "_")))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("    - name: No failed controls requiring automated remediation\n")
		sb.WriteString("      ansible.builtin.debug:\n")
		sb.WriteString("        msg: \"All controls compliant.\"\n")
	}

	return sb.String()
}

// GeneratePowerShellScript creates a standalone .ps1 remediation script for Windows targets.
func GeneratePowerShellScript(job *scans.Job, bm *audit.Benchmark) string {
	failedControlIDs := make(map[string]bool)
	if job != nil {
		for _, res := range job.Results {
			if res.Status == "failed" {
				failedControlIDs[res.ControlID] = true
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("# HardenX Auto-Generated PowerShell Remediation Script\n")
	if bm != nil {
		sb.WriteString(fmt.Sprintf("# Benchmark: %s (v%s)\n", bm.Title, bm.Version))
	}
	sb.WriteString("# Generated: " + fmt.Sprintf("%v", job != nil) + "\n\n")
	sb.WriteString("$ErrorActionPreference = 'Continue'\n")
	sb.WriteString("Write-Host '==================================================' -ForegroundColor Cyan\n")
	sb.WriteString("Write-Host 'Starting HardenX Automated Compliance Hardening' -ForegroundColor Cyan\n")
	sb.WriteString("Write-Host '==================================================' -ForegroundColor Cyan\n\n")

	if bm != nil {
		for _, ctrl := range bm.Controls {
			if len(failedControlIDs) > 0 && !failedControlIDs[ctrl.ID] {
				continue
			}

			sb.WriteString(fmt.Sprintf("Write-Host '[*] Remediating [%s]: %s' -ForegroundColor Yellow\n", ctrl.ID, strings.ReplaceAll(ctrl.Title, "'", "''")))
			cmds := ExtractCommands(ctrl.Remediation)
			if len(cmds) > 0 {
				for _, cmd := range cmds {
					sb.WriteString(fmt.Sprintf("%s\n", cmd))
				}
			} else if strings.TrimSpace(ctrl.Remediation) != "" {
				// Commented instruction
				sb.WriteString(fmt.Sprintf("# Instruction: %s\n", strings.ReplaceAll(ctrl.Remediation, "\n", "\n# ")))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("Write-Host '[+] Remediation cycle complete. Please rerun audit scan to verify compliance.' -ForegroundColor Green\n")
	return sb.String()
}

// GenerateBashScript creates a standalone .sh script for Linux targets.
func GenerateBashScript(job *scans.Job, bm *audit.Benchmark) string {
	failedControlIDs := make(map[string]bool)
	if job != nil {
		for _, res := range job.Results {
			if res.Status == "failed" {
				failedControlIDs[res.ControlID] = true
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("# HardenX Auto-Generated Bash Remediation Script\n")
	if bm != nil {
		sb.WriteString(fmt.Sprintf("# Benchmark: %s (v%s)\n", bm.Title, bm.Version))
	}
	sb.WriteString("set -uo pipefail\n\n")
	sb.WriteString("echo '[*] Executing HardenX Remediation...'\n\n")

	if bm != nil {
		for _, ctrl := range bm.Controls {
			if len(failedControlIDs) > 0 && !failedControlIDs[ctrl.ID] {
				continue
			}

			sb.WriteString(fmt.Sprintf("echo '[*] [%s] %s'\n", ctrl.ID, ctrl.Title))
			cmds := ExtractCommands(ctrl.Remediation)
			if len(cmds) > 0 {
				for _, cmd := range cmds {
					sb.WriteString(fmt.Sprintf("%s\n", cmd))
				}
			} else {
				sb.WriteString(fmt.Sprintf("# Manual configuration required:\n# %s\n", strings.ReplaceAll(ctrl.Remediation, "\n", "\n# ")))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("echo '[+] Finished remediation steps. Rerun scan to verify.'\n")
	return sb.String()
}

func escapeSingleLine(text string) string {
	clean := strings.ReplaceAll(text, "\n", " ")
	clean = strings.ReplaceAll(clean, "\"", "\\\"")
	if len(clean) > 200 {
		clean = clean[:197] + "..."
	}
	return clean
}
