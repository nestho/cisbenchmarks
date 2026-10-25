package runner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nestho/cisbenchmarks/platform/backend/internal/audit"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/connector"
)

type Result struct {
	ControlID  string `json:"control_id"`
	CheckType  string `json:"check_type"`
	Status     string `json:"status"`
	Actual     string `json:"actual"`
	Expected   string `json:"expected"`
	Evidence   string `json:"evidence"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

type Runner struct {
	Conn connector.Connector
}

func New(conn connector.Connector) *Runner {
	return &Runner{Conn: conn}
}

func (r *Runner) Run(ctx context.Context, bm *audit.Benchmark) []Result {
	var results []Result
	for _, ctrl := range bm.Controls {
		for _, chk := range ctrl.Checks {
			start := time.Now()
			res := Result{ControlID: ctrl.ID, CheckType: chk.Type, Expected: chk.Expected}
			select {
			case <-ctx.Done():
				res.Status = "skipped"
				res.Error = ctx.Err().Error()
				res.DurationMs = time.Since(start).Milliseconds()
				results = append(results, res)
				continue
			default:
			}

			switch chk.Type {
			case "command":
				out, exit, err := r.Conn.Run(chk.Command)
				res.Actual = out
				res.Evidence = fmt.Sprintf("COMMAND: %s\nEXIT: %d\nOUTPUT:\n%s", chk.Command, exit, out)
				if err != nil {
					res.Status = "error"
					res.Error = err.Error()
				} else {
					res.Status = eval(out, exit, chk)
				}
			case "powershell":
				var out string
				var exit int
				var err error
				if win, ok := r.Conn.(*connector.WinRM); ok {
					out, exit, err = win.RunPS(chk.Command)
				} else {
					out, exit, err = r.Conn.Run("powershell -NoProfile -NonInteractive -Command " + shellQuote(chk.Command))
				}
				res.Actual = out
				res.Evidence = fmt.Sprintf("POWERSHELL: %s\nEXIT: %d\nOUTPUT:\n%s", chk.Command, exit, out)
				if err != nil {
					res.Status = "error"
					res.Error = err.Error()
				} else {
					res.Status = eval(out, exit, chk)
				}
			case "registry":
				var out string
				var err error
				if win, ok := r.Conn.(*connector.WinRM); ok {
					out, err = win.ReadRegistry(chk.RegKey, chk.RegItem)
				} else {
					psCmd := fmt.Sprintf("(Get-ItemProperty -LiteralPath '%s' -Name '%s' -ErrorAction Stop).'%s'", chk.RegKey, chk.RegItem, chk.RegItem)
					out, _, err = r.Conn.Run(psCmd)
				}
				res.Actual = out
				res.Evidence = fmt.Sprintf("REGISTRY: %s\\%s\nVALUE:\n%s", chk.RegKey, chk.RegItem, out)
				if err != nil {
					res.Status = "error"
					res.Error = err.Error()
				} else {
					res.Status = evalRegistry(out, chk)
				}
			case "file":
				out, err := r.Conn.ReadFile(chk.Path)
				res.Actual = out
				res.Evidence = fmt.Sprintf("FILE: %s\nOUTPUT:\n%s", chk.Path, out)
				if err != nil {
					res.Status = "error"
					res.Error = err.Error()
				} else {
					res.Status = evalFile(out, chk)
				}
			default:
				res.Status = "skipped"
				res.Error = "unsupported check type: " + chk.Type
			}
			res.DurationMs = time.Since(start).Milliseconds()
			results = append(results, res)
		}
	}
	return results
}

func eval(out string, exit int, chk audit.Check) string {
	if chk.Regex != "" {
		re, err := regexp.Compile(chk.Regex)
		if err != nil {
			return "error"
		}
		if re.MatchString(out) {
			return "pass"
		}
		return "fail"
	}
	if chk.Expected != "" {
		if strings.Contains(out, chk.Expected) {
			return "pass"
		}
		return "fail"
	}
	if exit == 0 {
		return "pass"
	}
	return "fail"
}

func evalFile(out string, chk audit.Check) string {
	if chk.Contains != "" {
		if strings.Contains(out, chk.Contains) {
			return "pass"
		}
		return "fail"
	}
	if chk.Regex != "" {
		re, err := regexp.Compile(chk.Regex)
		if err != nil {
			return "error"
		}
		if re.MatchString(out) {
			return "pass"
		}
		return "fail"
	}
	return "pass"
}

func evalRegistry(out string, chk audit.Check) string {
	val := strings.TrimSpace(out)
	if chk.Expected != "" {
		if strings.EqualFold(val, strings.TrimSpace(chk.Expected)) || strings.Contains(val, chk.Expected) {
			return "pass"
		}
		return "fail"
	}
	if chk.ValueData != "" {
		if strings.EqualFold(val, strings.TrimSpace(chk.ValueData)) || strings.Contains(val, chk.ValueData) {
			return "pass"
		}
		return "fail"
	}
	if chk.Regex != "" {
		re, err := regexp.Compile(chk.Regex)
		if err != nil {
			return "error"
		}
		if re.MatchString(val) {
			return "pass"
		}
		return "fail"
	}
	if val != "" {
		return "pass"
	}
	return "fail"
}

func shellQuote(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "`\"") + "\""
}
