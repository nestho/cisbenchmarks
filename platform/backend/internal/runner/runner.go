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
