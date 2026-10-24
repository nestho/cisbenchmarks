package audit

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Benchmark struct {
	ID          string    `yaml:"id"`
	Title       string    `yaml:"title"`
	Version     string    `yaml:"version"`
	Technology  string    `yaml:"technology"`
	OS          string    `yaml:"os"`
	Controls    []Control `yaml:"controls"`
}

type Control struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Rationale   string   `yaml:"rationale"`
	Remediation string   `yaml:"remediation"`
	Scoring     string   `yaml:"scoring"`
	Profile     []string `yaml:"profile"`
	Checks      []Check  `yaml:"checks"`
}

type Check struct {
	Type        string `yaml:"type"`
	Command     string `yaml:"command"`
	Expected    string `yaml:"expected"`
	Regex       string `yaml:"regex"`
	Path        string `yaml:"path"`
	Contains    string `yaml:"contains"`
	Permission  string `yaml:"permission"`
	Owner       string `yaml:"owner"`
	Group       string `yaml:"group"`
	Service     string `yaml:"service"`
	Package     string `yaml:"package"`
	Version     string `yaml:"version"`
	Severity    string `yaml:"severity"`
}

func Load(path string) (*Benchmark, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type wrapper struct {
		Benchmark Benchmark `yaml:"benchmark"`
		Controls  []Control `yaml:"controls"`
	}
	var w wrapper
	if err := yaml.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	bm := w.Benchmark
	if bm.ID == "" && bm.Title == "" {
		// support flat format
		if err := yaml.Unmarshal(b, &bm); err != nil {
			return nil, err
		}
	}
	if len(bm.Controls) == 0 {
		bm.Controls = w.Controls
	}
	if bm.ID == "" || bm.Title == "" {
		return nil, fmt.Errorf("benchmark requires id and title")
	}
	if len(bm.Controls) == 0 {
		return nil, fmt.Errorf("benchmark requires at least one control")
	}
	for i := range bm.Controls {
		if bm.Controls[i].ID == "" || bm.Controls[i].Title == "" {
			return nil, fmt.Errorf("control %d requires id and title", i)
		}
		for j := range bm.Controls[i].Checks {
			if bm.Controls[i].Checks[j].Type == "" {
				return nil, fmt.Errorf("control %s check %d requires type", bm.Controls[i].ID, j)
			}
		}
	}
	return &bm, nil
}
