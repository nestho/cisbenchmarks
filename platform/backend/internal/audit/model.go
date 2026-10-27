package audit

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Benchmark struct {
	ID         string    `yaml:"id" json:"id"`
	Title      string    `yaml:"title" json:"title"`
	Version    string    `yaml:"version" json:"version"`
	Technology string    `yaml:"technology" json:"technology"`
	OS         string    `yaml:"os" json:"os"`
	Controls   []Control `yaml:"controls" json:"controls,omitempty"`
}

type Control struct {
	ID          string   `yaml:"id" json:"id"`
	Title       string   `yaml:"title" json:"title"`
	Description string   `yaml:"description" json:"description"`
	Rationale   string   `yaml:"rationale" json:"rationale"`
	Remediation string   `yaml:"remediation" json:"remediation"`
	Scoring     string   `yaml:"scoring" json:"scoring"`
	Profile     []string `yaml:"profile" json:"profile"`
	Checks      []Check  `yaml:"checks" json:"checks"`
}

type Check struct {
	Type       string `yaml:"type" json:"type"`
	RawType    string `yaml:"raw_type" json:"raw_type,omitempty"`
	Command    string `yaml:"command" json:"command,omitempty"`
	Expected   string `yaml:"expected" json:"expected,omitempty"`
	Regex      string `yaml:"regex" json:"regex,omitempty"`
	Path       string `yaml:"path" json:"path,omitempty"`
	Contains   string `yaml:"contains" json:"contains,omitempty"`
	RegKey     string `yaml:"reg_key" json:"reg_key,omitempty"`
	RegItem    string `yaml:"reg_item" json:"reg_item,omitempty"`
	Permission string `yaml:"permission" json:"permission,omitempty"`
	Owner      string `yaml:"owner" json:"owner,omitempty"`
	Group      string `yaml:"group" json:"group,omitempty"`
	Service    string `yaml:"service" json:"service,omitempty"`
	Package    string `yaml:"package" json:"package,omitempty"`
	Version    string `yaml:"version" json:"version,omitempty"`
	Severity   string `yaml:"severity" json:"severity,omitempty"`
	Info       string `yaml:"info" json:"info,omitempty"`
	Solution   string `yaml:"solution" json:"solution,omitempty"`
	Reference  string `yaml:"reference" json:"reference,omitempty"`
	SeeAlso    string `yaml:"see_also" json:"see_also,omitempty"`
	ValueData  string `yaml:"value_data" json:"value_data,omitempty"`
	ValueType  string `yaml:"value_type" json:"value_type,omitempty"`
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
