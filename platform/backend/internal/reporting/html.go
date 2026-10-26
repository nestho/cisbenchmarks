package reporting

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/nestho/hardenx/platform/backend/internal/scans"
)

const tpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>OpenCompliance Report</title>
<style>
body{font-family:Arial,sans-serif;margin:24px;color:#222}
h1{color:#1f3864}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:8px;text-align:left}
th{background:#f2f2f2}
.pass{color:green;font-weight:bold}
.fail{color:red;font-weight:bold}
.error{color:orange;font-weight:bold}
.skipped{color:gray}
</style></head><body>
<h1>OpenCompliance Report</h1>
<p>Job: {{.ID}} | Benchmark: {{.BenchmarkID}} | Profile: {{.Profile}} | Status: {{.Status}}</p>
<p>Created: {{.CreatedAt}} {{if .FinishedAt}}Finished: {{.FinishedAt}}{{end}}</p>
<table><tr><th>#</th><th>Control</th><th>Type</th><th>Status</th><th>Duration (ms)</th></tr>
{{range $i, $r := .Results}}
<tr><td>{{add $i 1}}</td><td>{{$r.ControlID}}</td><td>{{$r.CheckType}}</td><td class="{{$r.Status}}">{{$r.Status}}</td><td>{{$r.DurationMs}}</td></tr>
{{end}}
</table>
<h2>Evidence</h2>
{{range .Results}}
<details><summary>{{.ControlID}} - {{.Status}}</summary><pre>{{.Evidence}}</pre></details>
{{end}}
</body></html>`

func RenderHTML(job *scans.Job) (string, error) {
	t, err := template.New("report").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).Parse(tpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, job); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Score(job *scans.Job) float64 {
	if len(job.Results) == 0 {
		return 0
	}
	pass := 0
	for _, r := range job.Results {
		if r.Status == "pass" {
			pass++
		}
	}
	return float64(pass) / float64(len(job.Results)) * 100
}

var _ = fmt.Sprintf