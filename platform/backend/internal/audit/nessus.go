package audit

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	reCustomItem = regexp.MustCompile(`(?s)<custom_item>(.*?)</custom_item>`)
	reReport     = regexp.MustCompile(`(?s)<report\b[^>]*>(.*?)</report>`)
	reDisplayName= regexp.MustCompile(`(?s)<display_name>(.*?)</display_name>`)
	reSpecVersion= regexp.MustCompile(`(?s)<version>(.*?)</version>`)
	reCheckType  = regexp.MustCompile(`<check_type:"([^"]+)"`)
)

func LoadNessus(path string) (*Benchmark, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(b)

	title := ""
	if m := reDisplayName.FindStringSubmatch(text); len(m) > 1 {
		title = strings.TrimSpace(m[1])
	}
	if title == "" {
		title = baseName(path)
	}
	version := ""
	if m := reSpecVersion.FindStringSubmatch(text); len(m) > 1 {
		version = strings.TrimSpace(m[1])
	}
	platform := ""
	if m := reCheckType.FindStringSubmatch(text); len(m) > 1 {
		platform = strings.TrimSpace(m[1])
	}

	bm := &Benchmark{
		ID:         slug(title),
		Title:      title,
		Version:    version,
		Technology: platform,
		OS:         platform,
	}

	items := reCustomItem.FindAllStringSubmatch(text, -1)
	for i, m := range items {
		fields := parseNessusFields(m[1])
		rawType := strings.ToUpper(strings.TrimSpace(fields["type"]))
		ctrl := Control{
			ID:          fmt.Sprintf("item-%d", i+1),
			Title:       firstNonEmpty(fields["description"], fmt.Sprintf("Custom item %d", i+1)),
			Description: fields["info"],
			Rationale:   fields["info"],
			Remediation: fields["solution"],
			Scoring:     "scored",
			Profile:     []string{"level1"},
			Checks: []Check{{
				Type:        mapNessusType(rawType),
				RawType:     rawType,
				Command:     firstNonEmpty(fields["cmd"], fields["command"], fields["sql_request"], fields["query"]),
				Expected:    firstNonEmpty(fields["expect"], fields["value_data"]),
				Regex:       fields["regex"],
				Path:        firstNonEmpty(fields["file"], fields["reg_key"]),
				RegKey:      fields["reg_key"],
				RegItem:     fields["reg_item"],
				Contains:    fields["value_data"],
				Permission:  fields["acl_option"],
				Owner:       "",
				Group:       "",
				Service:     fields["service"],
				Package:     fields["package"],
				Version:     fields["version"],
				Severity:    "medium",
				Info:        fields["info"],
				Solution:    fields["solution"],
				Reference:   fields["reference"],
				SeeAlso:     fields["see_also"],
				ValueData:   fields["value_data"],
				ValueType:   fields["value_type"],
			}},
		}
		bm.Controls = append(bm.Controls, ctrl)
	}

	if len(bm.Controls) == 0 {
		return nil, fmt.Errorf("no custom_item found in %s", path)
	}
	return bm, nil
}

func parseNessusFields(block string) map[string]string {
	fields := map[string]string{}
	lines := strings.Split(block, "\n")
	var key string
	var val strings.Builder
	inQuote := false
	quoteChar := byte(0)
	flush := func() {
		if key != "" {
			fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(val.String())
		}
		key = ""
		val.Reset()
		inQuote = false
		quoteChar = 0
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if inQuote {
				val.WriteString("\n")
			}
			continue
		}
		// new key?
		if !inQuote {
			if idx := strings.Index(trimmed, ":"); idx > 0 {
				k := strings.TrimSpace(trimmed[:idx])
				// ensure key is identifier-like
				if isIdent(k) {
					// flush previous
					flush()
					key = k
					rest := strings.TrimSpace(trimmed[idx+1:])
					if rest == "" {
						continue
					}
					// handle quote
					if rest[0] == '"' || rest[0] == '\'' {
						quoteChar = rest[0]
						rest = rest[1:]
						if len(rest) > 0 && rest[len(rest)-1] == quoteChar {
							val.WriteString(rest[:len(rest)-1])
							inQuote = false
							quoteChar = 0
						} else {
							val.WriteString(rest)
							inQuote = true
						}
					} else {
						val.WriteString(rest)
						inQuote = false
					}
					continue
				}
			}
		}
		if inQuote {
			// check closing quote
			if i := strings.IndexByte(trimmed, quoteChar); i >= 0 {
				val.WriteString("\n")
				val.WriteString(trimmed[:i])
				inQuote = false
				quoteChar = 0
			} else {
				val.WriteString("\n")
				val.WriteString(trimmed)
			}
		} else {
			// continuation? append
			if key != "" {
				val.WriteString(" ")
				val.WriteString(trimmed)
			}
		}
	}
	flush()
	return fields
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !( (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' ) {
			return false
		}
	}
	return true
}

func mapNessusType(t string) string {
	switch t {
	case "CMD_EXEC", "CMD":
		return "command"
	case "SQL_EXEC", "SQL_CHECK", "SQL", "DATABASE", "POSTGRESQL_QUERY", "MYSQL_QUERY":
		return "sql"
	case "AUDIT_POWERSHELL", "POWERSHELL":
		return "powershell"
	case "FILE_CONTENT_CHECK", "FILE_CHECK":
		return "file"
	case "REGISTRY_SETTING", "REG_CHECK", "REGISTRY":
		return "registry"
	case "SERVICE_POLICY", "SERVICE":
		return "service"
	case "PACKAGE":
		return "package"
	default:
		return "script"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "benchmark"
	}
	return out
}

func baseName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}