// Package config implements a minimal YAML-subset parser and the proxy
// configuration structure. Only nested maps of scalars and dash-lists of
// strings are supported (enough for kasa2onvif configuration).
package config

import (
	"fmt"
	"strings"
)

type yamlLine struct {
	indent  int
	text    string
	isItem  bool
	isPlain bool // plain scalar (no ':' separator)
}

func scanYAML(text string) []yamlLine {
	var out []yamlLine
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		s := strings.TrimLeft(line, " \t")
		if s == "" || strings.HasPrefix(s, "#") || s == "---" {
			continue
		}
		indent := len(line) - len(s)
		if strings.HasPrefix(s, "- ") {
			item := strings.TrimSpace(s[2:])
			if idx := commentIndex(item); idx >= 0 {
				item = strings.TrimRight(item[:idx], " \t")
			}
			out = append(out, yamlLine{indent: indent, text: unquote(item), isItem: true})
			continue
		}
		if idx := commentIndex(s); idx >= 0 {
			s = strings.TrimRight(s[:idx], " \t")
		}
		// ":" followed by space/EOL marks the key separator
		idx := keyColon(s)
		out = append(out, yamlLine{indent: indent, text: s, isPlain: idx < 0})
	}
	return out
}

func commentIndex(s string) int {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') && !inS && !inD {
				return i
			}
		}
	}
	return -1
}

func keyColon(s string) int {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ':':
			if !inS && !inD && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
				return i
			}
		}
	}
	return -1
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ParseYAML parses the supported YAML subset into nested maps with string
// values (lists become []string).
func ParseYAML(text string) (map[string]any, error) {
	lines := scanYAML(text)
	v, _, err := parseBlock(lines, 0, firstIndent(lines))
	if err != nil {
		return nil, err
	}
	if m, ok := v.(map[string]any); ok {
		return m, nil
	}
	if v == nil {
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("yaml: unexpected document value")
}

func firstIndent(lines []yamlLine) int {
	if len(lines) == 0 {
		return 0
	}
	return lines[0].indent
}

func parseBlock(lines []yamlLine, i, indent int) (any, int, error) {
	if i >= len(lines) {
		return nil, i, nil
	}
	if lines[i].isItem {
		var out []string
		for i < len(lines) && lines[i].indent == indent && lines[i].isItem {
			out = append(out, lines[i].text)
			i++
		}
		return out, i, nil
	}
	if lines[i].isPlain {
		return nil, i, fmt.Errorf("yaml: unexpected scalar: %q", lines[i].text)
	}

	m := map[string]any{}
	for i < len(lines) && lines[i].indent == indent && !lines[i].isItem {
		if lines[i].isPlain {
			return nil, i, fmt.Errorf("yaml: unexpected scalar: %q", lines[i].text)
		}
		idx := keyColon(lines[i].text)
		key := strings.TrimSpace(lines[i].text[:idx])
		rest := strings.TrimSpace(lines[i].text[idx+1:])
		i++
		if rest != "" {
			m[key] = unquote(rest)
			continue
		}
		if i < len(lines) && lines[i].indent > indent {
			v, ni, err := parseBlock(lines, i, lines[i].indent)
			if err != nil {
				return nil, i, err
			}
			m[key] = v
			i = ni
			continue
		}
		m[key] = ""
	}
	return m, i, nil
}
