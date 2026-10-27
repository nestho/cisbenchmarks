package layer8

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nestho/hardenx/platform/backend/internal/connector"
)

type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "CRITICAL"
	SeverityHigh     FindingSeverity = "HIGH"
	SeverityMedium   FindingSeverity = "MEDIUM"
	SeverityLow      FindingSeverity = "LOW"
	SeverityClean    FindingSeverity = "CLEAN"
)

type AnomalyFinding struct {
	ID          string          `json:"id"`
	RuleName    string          `json:"rule_name"`
	Category    string          `json:"category"`
	Severity    FindingSeverity `json:"severity"`
	Target      string          `json:"target"` // PID, Driver, File, Pipe
	Description string          `json:"description"`
	Evidence    string          `json:"evidence"`
	MITRETactic string          `json:"mitre_tactic"`
	Remediation string          `json:"remediation"`
}

type Layer8Report struct {
	TargetHost       string           `json:"target_host"`
	Platform         string           `json:"platform"`
	AuditTime        time.Time        `json:"audit_time"`
	TotalChecks      int              `json:"total_checks"`
	AnomaliesFound   int              `json:"anomalies_found"`
	HighestSeverity  FindingSeverity  `json:"highest_severity"`
	Findings         []AnomalyFinding `json:"findings"`
	ExecutionSummary string           `json:"execution_summary"`
}

// Known vulnerable / abused BYOVD drivers
var VulnerableDriverHashes = map[string]string{
	"gdrv.sys":       "Gigabyte GDrv (CVE-2018-19320) - Ring0 Arbitrary RW",
	"mhyprot2.sys":   "Genshin Impact Anti-Cheat (Abused by Ransomware) - Ring0 RW",
	"procexp.sys":    "Process Explorer signed driver used for arbitrary process kill",
	"aswbids.sys":    "Avast Anti-rootkit driver abused for privilege escalation",
	"dbutil_2_3.sys": "Dell dbutil (CVE-2021-21551) - Ring0 physical memory RW",
	"rtcore64.sys":   "MSI Afterburner RTCore64 (CVE-2019-16098) - Arbitrary I/O port RW",
	"ene.sys":        "ENE Technology RGB driver (CVE-2020-12440)",
}

// Known suspicious named pipes (Cobalt Strike, Metasploit, Covenant, Sliver)
var SuspiciousPipes = []string{
	"msagent_", "status_", "msse-", "postex_", "spoolss_", "win_svc_",
	"pipename", "demo_pipe", "sliver", "covenant",
}

// AuditLinuxHost runs comprehensive Layer 8 Memory & Rootkit checks on a Linux target
func AuditLinuxHost(conn connector.Connector, host string) *Layer8Report {
	rep := &Layer8Report{
		TargetHost:      host,
		Platform:        "linux",
		AuditTime:       time.Now(),
		Findings:        make([]AnomalyFinding, 0),
		HighestSeverity: SeverityClean,
	}

	// 1. Unlinked running binaries (/proc/*/exe -> (deleted))
	rep.TotalChecks++
	cmdUnlinked := `ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)'`
	out, _, _ := conn.Run(cmdUnlinked)
	if strings.Contains(out, "(deleted)") {
		// Filter out standard benign daemons if any, flag suspicious /tmp, /dev/shm, /var/tmp
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			isTmp := strings.Contains(line, "/tmp") || strings.Contains(line, "/dev/shm") || strings.Contains(line, "/var/tmp")
			sev := SeverityHigh
			if isTmp {
				sev = SeverityCritical
			}
			rep.Findings = append(rep.Findings, AnomalyFinding{
				ID:          "L8-LIN-001",
				RuleName:    "Unlinked Executable Running in RAM",
				Category:    "Process Anomaly / Fileless Execution",
				Severity:    sev,
				Target:      line,
				Description: "Process executable was unlinked from disk while remaining active in memory. Classic tactic for fileless droppers.",
				Evidence:    line,
				MITRETactic: "Defense Evasion (T1070.004) / Process Injection",
				Remediation: "Identify parent process, isolate PID, acquire core dump via gcore, and terminate process.",
			})
		}
	}

	// 2. Anonymous RWX memory mappings
	rep.TotalChecks++
	cmdRWX := `grep -E '^[0-9a-f]+-[0-9a-f]+ rwxp' /proc/[0-9]*/maps 2>/dev/null | grep -v '\[heap\]' | head -n 30`
	outRWX, _, _ := conn.Run(cmdRWX)
	if len(strings.TrimSpace(outRWX)) > 0 {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-LIN-002",
			RuleName:    "Anonymous RWX Executable Memory Page",
			Category:    "Memory Integrity / In-Memory Payload",
			Severity:    SeverityHigh,
			Target:      "Process Virtual Memory Mappings",
			Description: "Detected anonymous memory segments mapped with simultaneous Read, Write, and Execute (RWX) permissions outside heap.",
			Evidence:    outRWX,
			MITRETactic: "Defense Evasion (T1055) / Process Injection",
			Remediation: "Inspect memory pages of flagged PIDs with gdb or pmdump; verify if JIT engine or injected shellcode.",
		})
	}

	// 3. Userspace Hooking: /etc/ld.so.preload inspection
	rep.TotalChecks++
	preloadOut, errPreload := conn.ReadFile("/etc/ld.so.preload")
	if errPreload == nil && len(strings.TrimSpace(preloadOut)) > 0 {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-LIN-003",
			RuleName:    "Global LD_PRELOAD Userspace Hooking Active",
			Category:    "Userspace Rootkit / Dynamic Linker Hijacking",
			Severity:    SeverityCritical,
			Target:      "/etc/ld.so.preload",
			Description: "/etc/ld.so.preload contains active library paths. Every dynamically linked binary loads these libraries first.",
			Evidence:    preloadOut,
			MITRETactic: "Persistence / Privilege Escalation (T1574.006)",
			Remediation: "Analyze libraries referenced in /etc/ld.so.preload for malicious symbols; remove unauthorized entries immediately.",
		})
	}

	// 4. Kernel Taint & LKM Anomaly Check
	rep.TotalChecks++
	taintedVal, errTaint := conn.ReadFile("/proc/sys/kernel/tainted")
	if errTaint == nil {
		tVal, _ := strconv.Atoi(strings.TrimSpace(taintedVal))
		if tVal > 0 {
			var reasons []string
			if tVal&1 != 0 {
				reasons = append(reasons, "Proprietary/Non-GPL Module Loaded (bit 0)")
			}
			if tVal&(1<<12) != 0 {
				reasons = append(reasons, "Out-of-tree Driver Loaded (bit 12)")
			}
			if tVal&(1<<13) != 0 {
				reasons = append(reasons, "Unsigned Kernel Module Loaded (bit 13)")
			}
			if len(reasons) > 0 {
				rep.Findings = append(rep.Findings, AnomalyFinding{
					ID:          "L8-LIN-004",
					RuleName:    "Kernel Tainted / Unsigned LKM Active",
					Category:    "Kernel Rootkit / Module Integrity",
					Severity:    SeverityMedium,
					Target:      fmt.Sprintf("/proc/sys/kernel/tainted (%d)", tVal),
					Description: fmt.Sprintf("Kernel is tainted: %s", strings.Join(reasons, ", ")),
					Evidence:    fmt.Sprintf("Taint Value: %d\nFlags: %s", tVal, strings.Join(reasons, ", ")),
					MITRETactic: "Persistence / Defense Evasion (T1547.006)",
					Remediation: "Cross-examine loaded LKMs against distribution base via lsmod and modinfo.",
				})
			}
		}
	}

	// 5. Hidden Process Cross-Check (/proc vs kill -0)
	rep.TotalChecks++
	cmdHidden := `for p in $(ls -d /proc/[0-9]* 2>/dev/null | cut -d/ -f3); do if ! ps -p $p >/dev/null 2>&1; then echo "HIDDEN_PID:$p"; fi; done`
	outHidden, _, _ := conn.Run(cmdHidden)
	if strings.Contains(outHidden, "HIDDEN_PID:") {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-LIN-005",
			RuleName:    "Hidden Process Detected (getdents hook)",
			Category:    "Kernel Rootkit / Process Cloaking",
			Severity:    SeverityCritical,
			Target:      outHidden,
			Description: "PID exists in /proc but is invisible to standard ps utilities, indicating sys_getdents hooking or readdir modification.",
			Evidence:    outHidden,
			MITRETactic: "Defense Evasion (T1564.001) / Rootkit",
			Remediation: "Forensically image system RAM immediately. Check for sys_call_table modifications or Diamorphine/Reptile rootkits.",
		})
	}

	// 6. eBPF Malicious Program Audit
	rep.TotalChecks++
	outBPF, exitBPF, _ := conn.Run("bpftool prog list 2>/dev/null || ip link show type xdp 2>/dev/null")
	if exitBPF == 0 && len(strings.TrimSpace(outBPF)) > 0 {
		// Verify if unknown eBPF filters are attached
		if strings.Contains(outBPF, "xdp") || strings.Contains(outBPF, "tracepoint") || strings.Contains(outBPF, "kprobe") {
			rep.Findings = append(rep.Findings, AnomalyFinding{
				ID:          "L8-LIN-006",
				RuleName:    "Active eBPF Probe / XDP Filter Enumerated",
				Category:    "eBPF Observability & Stealth Hooking",
				Severity:    SeverityLow,
				Target:      "Kernel eBPF Subsystem",
				Description: "Active eBPF kprobes or XDP programs detected. Verify against authorized monitoring agents.",
				Evidence:    outBPF,
				MITRETactic: "Persistence / Defense Evasion (T1547)",
				Remediation: "Validate author and origin of all loaded eBPF programs via bpftool prog dump xlated.",
			})
		}
	}

	calculateReportSummary(rep)
	return rep
}

// AuditWindowsHost runs Layer 8 Memory, PPID, Driver, and Persistence checks via WinRM
func AuditWindowsHost(conn connector.Connector, host string) *Layer8Report {
	rep := &Layer8Report{
		TargetHost:      host,
		Platform:        "windows",
		AuditTime:       time.Now(),
		Findings:        make([]AnomalyFinding, 0),
		HighestSeverity: SeverityClean,
	}

	// 1. PPID Spoofing & Anomalous Process Parentage
	rep.TotalChecks++
	psPPID := `Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Where-Object { ($_.Name -eq "cmd.exe" -or $_.Name -eq "powershell.exe") -and ($_.ParentProcessId -eq 4 -or $_.ParentProcessId -eq 0) } | ConvertTo-Json`
	outPPID, _, _ := conn.Run(psPPID)
	if len(strings.TrimSpace(outPPID)) > 5 && !strings.Contains(outPPID, "null") {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-WIN-001",
			RuleName:    "PPID Spoofing / Orphaned Shell Anomaly",
			Category:    "Process Anomaly / PPID Spoofing",
			Severity:    SeverityCritical,
			Target:      "Parent Process ID spoofing",
			Description: "Command prompt or PowerShell running with System (PID 4) as direct parent without standard intermediate services.",
			Evidence:    outPPID,
			MITRETactic: "Defense Evasion (T1134.004) / Access Token Manipulation",
			Remediation: "Isolate host, terminate rogue shell, inspect event log 4688 with command line auditing.",
		})
	}

	// 2. Suspicious Named Pipes (C2 Beacons)
	rep.TotalChecks++
	psPipes := `[System.IO.Directory]::GetFiles("\\.\\pipe\\") | ConvertTo-Json`
	outPipes, _, _ := conn.Run(psPipes)
	for _, badPipe := range SuspiciousPipes {
		if strings.Contains(strings.ToLower(outPipes), badPipe) {
			rep.Findings = append(rep.Findings, AnomalyFinding{
				ID:          "L8-WIN-002",
				RuleName:    "Suspicious C2 Named Pipe Discovered",
				Category:    "Command & Control / Named Pipe Beaconing",
				Severity:    SeverityCritical,
				Target:      badPipe,
				Description: fmt.Sprintf("Found named pipe matching known C2 framework default pattern: %s", badPipe),
				Evidence:    outPipes,
				MITRETactic: "Command and Control (T1071) / Lateral Movement",
				Remediation: "Map named pipe handle to PID using handle64.exe or Process Hacker; isolate infected process.",
			})
			break
		}
	}

	// 3. Vulnerable BYOVD Driver Check
	rep.TotalChecks++
	psDrivers := `Get-CimInstance Win32_SystemDriver | Select-Object Name, PathName, State | ConvertTo-Json`
	outDrivers, _, _ := conn.Run(psDrivers)
	for badDriver, desc := range VulnerableDriverHashes {
		if strings.Contains(strings.ToLower(outDrivers), strings.ToLower(badDriver)) {
			rep.Findings = append(rep.Findings, AnomalyFinding{
				ID:          "L8-WIN-003",
				RuleName:    "Known Vulnerable BYOVD Driver Loaded",
				Category:    "Kernel Exploitation / BYOVD",
				Severity:    SeverityCritical,
				Target:      badDriver,
				Description: fmt.Sprintf("Loaded driver is vulnerable to BYOVD abuse: %s", desc),
				Evidence:    fmt.Sprintf("Driver: %s\nDetails: %s", badDriver, desc),
				MITRETactic: "Privilege Escalation / Defense Evasion (T1068 / T1562.001)",
				Remediation: "Enable Microsoft Vulnerable Driver Blocklist (HVCI / WDAC); stop driver service and delete sys binary.",
			})
		}
	}

	// 4. WMI Event Persistence Check
	rep.TotalChecks++
	psWMI := `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Select-Object Name, CommandLineTemplate | ConvertTo-Json`
	outWMI, _, _ := conn.Run(psWMI)
	if len(strings.TrimSpace(outWMI)) > 5 && !strings.Contains(outWMI, "null") && strings.Contains(outWMI, "CommandLineTemplate") {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-WIN-004",
			RuleName:    "WMI Event Consumer Persistence Active",
			Category:    "Persistence / WMI Event Subscription",
			Severity:    SeverityHigh,
			Target:      "root\\subscription:__EventConsumer",
			Description: "Permanent WMI Event Consumer configured to trigger commands upon system events.",
			Evidence:    outWMI,
			MITRETactic: "Persistence (T1546.003) / Event Triggered Execution",
			Remediation: "Remove unauthorized WMI subscriptions via Get-CimInstance and Remove-CimInstance.",
		})
	}

	calculateReportSummary(rep)
	return rep
}

// AuditNetworkAppliance runs firmware and administrative privilege verification
func AuditNetworkAppliance(conn connector.Connector, host, devType string) *Layer8Report {
	rep := &Layer8Report{
		TargetHost:      host,
		Platform:        devType,
		AuditTime:       time.Now(),
		Findings:        make([]AnomalyFinding, 0),
		HighestSeverity: SeverityClean,
	}

	// 1. Unsigned files in bootflash
	rep.TotalChecks++
	outDir, _, _ := conn.Run("dir bootflash: | include .bin|.py|.elf|.sh")
	if len(strings.TrimSpace(outDir)) > 0 {
		for _, line := range strings.Split(outDir, "\n") {
			l := strings.ToLower(line)
			if strings.Contains(l, ".py") || strings.Contains(l, ".sh") || strings.Contains(l, ".elf") {
				rep.Findings = append(rep.Findings, AnomalyFinding{
					ID:          "L8-NET-001",
					RuleName:    "Unsigned Script / Binary in Network Appliance Flash",
					Category:    "Firmware Tampering / Appliance Implant",
					Severity:    SeverityCritical,
					Target:      line,
					Description: "Detected anomalous script or non-system binary in flash storage (possible Synful Knock or router implant).",
					Evidence:    line,
					MITRETactic: "Persistence (T1542.001) / Pre-OS Boot",
					Remediation: "Compare image hash with Cisco/Vendor Golden Hash; remove unauthorized files from flash.",
				})
			}
		}
	}

	// 2. Hidden privilege-15 accounts
	rep.TotalChecks++
	outUsers, _, _ := conn.Run("show running-config | include username.*privilege 15")
	if len(strings.TrimSpace(outUsers)) > 0 {
		rep.Findings = append(rep.Findings, AnomalyFinding{
			ID:          "L8-NET-002",
			RuleName:    "Privilege-15 Administrative Accounts Enumerated",
			Category:    "Access Control / Backdoor Account",
			Severity:    SeverityMedium,
			Target:      "Running Configuration AAA",
			Description: "Active privilege 15 accounts discovered in local configuration. Verify all accounts belong to authorized admins.",
			Evidence:    outUsers,
			MITRETactic: "Persistence (T1078.001) / Valid Accounts",
			Remediation: "Enforce centralized TACACS+/RADIUS authentication; eliminate local privilege 15 accounts.",
		})
	}

	calculateReportSummary(rep)
	return rep
}

func calculateReportSummary(rep *Layer8Report) {
	rep.AnomaliesFound = len(rep.Findings)
	highest := SeverityClean
	for _, f := range rep.Findings {
		switch f.Severity {
		case SeverityCritical:
			highest = SeverityCritical
		case SeverityHigh:
			if highest != SeverityCritical {
				highest = SeverityHigh
			}
		case SeverityMedium:
			if highest != SeverityCritical && highest != SeverityHigh {
				highest = SeverityMedium
			}
		case SeverityLow:
			if highest == SeverityClean {
				highest = SeverityLow
			}
		}
	}
	rep.HighestSeverity = highest
	rep.ExecutionSummary = fmt.Sprintf("Completed %d in-memory compromise checks. Detected %d anomalous indicators. Posture state: %s.",
		rep.TotalChecks, rep.AnomaliesFound, rep.HighestSeverity)
}
