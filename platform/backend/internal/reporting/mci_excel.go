package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nestho/hardenx/platform/backend/internal/audit"
	"github.com/nestho/hardenx/platform/backend/internal/scans"
)

// GenerateMCIExcel executes the python reporting bridge to generate the official 15-sheet MCI workbook.
func GenerateMCIExcel(job *scans.Job, bm *audit.Benchmark, outputPath string) error {
	tmpDir := os.TempDir()
	jobFile := filepath.Join(tmpDir, fmt.Sprintf("job_%s.json", job.ID))
	bmFile := filepath.Join(tmpDir, fmt.Sprintf("bm_%s.json", job.ID))

	jobBytes, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}
	if err := os.WriteFile(jobFile, jobBytes, 0644); err != nil {
		return fmt.Errorf("failed to write tmp job file: %w", err)
	}
	defer os.Remove(jobFile)

	args := []string{
		"tools/generate_mci_report.py",
		"--job-json", jobFile,
		"--output", outputPath,
	}

	// Try finding tools/generate_mci_report.py
	scriptCandidates := []string{
		"tools/generate_mci_report.py",
		"../../tools/generate_mci_report.py",
		"/Users/nestho/hardenx/tools/generate_mci_report.py",
	}
	scriptPath := ""
	for _, p := range scriptCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			scriptPath = p
			break
		}
	}
	if scriptPath == "" {
		return fmt.Errorf("tools/generate_mci_report.py not found")
	}
	args[0] = scriptPath

	if bm != nil {
		bmBytes, err := json.Marshal(bm)
		if err == nil {
			if err := os.WriteFile(bmFile, bmBytes, 0644); err == nil {
				defer os.Remove(bmFile)
				args = append(args, "--benchmark-json", bmFile)
			}
		}
	}

	cmd := exec.Command("python3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mci excel generator failed: %s (err: %w)", string(out), err)
	}

	return nil
}
