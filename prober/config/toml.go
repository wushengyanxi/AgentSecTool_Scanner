// Package config 提供一个极简 TOML 解析器，零第三方依赖（纯标准库）。
//
// 支持的子集（不求完整 TOML 规范）：
//   - [section] 段
//   - key = value，value 可为：带引号字符串、整数、布尔 true/false
//   - key = ["a", "b", "c"] 字符串数组、key = [1, 2, 3] 整数数组
//   - # 行注释、空行
//
// 不支持：浮点数、日期、嵌套表、多行字符串、行内注释（# 出现在引号外即视为注释起点除外）。
package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Config 是解析后的配置，按 section -> key -> value 组织。
// value 的动态类型为 string、int64、bool、[]string 或 []int64 之一。
// 段外（无 [section] 前缀）的键归入空字符串 "" 这个默认段。
type Config struct {
	sections map[string]map[string]any
}

// Parse 解析 TOML 文本，返回 *Config。解析失败时返回带行号与原因的 error。
func Parse(data []byte) (*Config, error) {
	cfg := &Config{sections: map[string]map[string]any{
		"": {}, // 默认段，承接段外的键值对
	}}
	current := ""

	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name, err := parseSectionHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			current = name
			if _, ok := cfg.sections[name]; !ok {
				cfg.sections[name] = map[string]any{}
			}
			continue
		}

		key, val, err := parseKeyValue(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		cfg.sections[current][key] = val
	}

	return cfg, nil
}

// stripComment 去掉行尾注释。引号内的 # 不算注释。
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// parseSectionHeader 解析形如 [name] 的段头，返回段名。
func parseSectionHeader(line string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("section 头缺少闭合的 ']': %q", line)
	}
	name := strings.TrimSpace(line[1 : len(line)-1])
	if name == "" {
		return "", fmt.Errorf("section 名为空: %q", line)
	}
	return name, nil
}

// parseKeyValue 解析形如 key = value 的一行，返回键与已转换类型的值。
func parseKeyValue(line string) (string, any, error) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", nil, fmt.Errorf("非法行，缺少 '=': %q", line)
	}
	key := strings.TrimSpace(line[:eq])
	if key == "" {
		return "", nil, fmt.Errorf("非法行，键为空: %q", line)
	}
	rawVal := strings.TrimSpace(line[eq+1:])
	if rawVal == "" {
		return "", nil, fmt.Errorf("非法行，键 %q 的值为空", key)
	}

	val, err := parseValue(rawVal)
	if err != nil {
		return "", nil, fmt.Errorf("键 %q: %w", key, err)
	}
	return key, val, nil
}

// parseValue 把一个标量或数组的字面量转换为 Go 值。
func parseValue(s string) (any, error) {
	if strings.HasPrefix(s, "[") {
		return parseArray(s)
	}
	return parseScalar(s)
}

// parseScalar 转换字符串/整数/布尔标量。
func parseScalar(s string) (any, error) {
	// 带引号字符串
	if strings.HasPrefix(s, `"`) {
		if len(s) < 2 || !strings.HasSuffix(s, `"`) {
			return nil, fmt.Errorf("字符串缺少闭合引号: %q", s)
		}
		return s[1 : len(s)-1], nil
	}
	// 布尔
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	// 整数
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	return nil, fmt.Errorf("无法识别的值 %q（需为带引号字符串、整数或 true/false）", s)
}

// parseArray 解析 ["a","b"] 或 [1,2,3]。空数组返回 []string{}。
// 元素类型必须一致，否则报错。
func parseArray(s string) (any, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("数组缺少闭合的 ']': %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []string{}, nil
	}

	parts := splitArrayElems(inner)
	elems := make([]any, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("数组含空元素: %q", s)
		}
		v, err := parseScalar(p)
		if err != nil {
			return nil, fmt.Errorf("数组元素 %w", err)
		}
		elems = append(elems, v)
	}

	// 依据首元素类型收敛为 []string 或 []int64。
	switch elems[0].(type) {
	case string:
		out := make([]string, len(elems))
		for i, e := range elems {
			str, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("数组元素类型不一致（既有字符串又有非字符串）: %q", s)
			}
			out[i] = str
		}
		return out, nil
	case int64:
		out := make([]int64, len(elems))
		for i, e := range elems {
			n, ok := e.(int64)
			if !ok {
				return nil, fmt.Errorf("数组元素类型不一致（既有整数又有非整数）: %q", s)
			}
			out[i] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("不支持的数组元素类型（仅支持字符串数组与整数数组）: %q", s)
	}
}

// splitArrayElems 按逗号切分数组内部，忽略引号内的逗号。
func splitArrayElems(inner string) []string {
	var parts []string
	var buf strings.Builder
	inQuote := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch c {
		case '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case ',':
			if inQuote {
				buf.WriteByte(c)
			} else {
				parts = append(parts, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteByte(c)
		}
	}
	parts = append(parts, buf.String())
	return parts
}

// Sections 返回原始 section -> key -> value 映射（直接引用，非拷贝）。
func (c *Config) Sections() map[string]map[string]any {
	return c.sections
}

// lookup 取出某段某键的原始值。
func (c *Config) lookup(section, key string) (any, bool) {
	sec, ok := c.sections[section]
	if !ok {
		return nil, false
	}
	v, ok := sec[key]
	return v, ok
}

// GetString 返回字符串值；缺失或类型不符时返回 def。
func (c *Config) GetString(section, key, def string) string {
	if v, ok := c.lookup(section, key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// GetInt 返回整数值；缺失或类型不符时返回 def。
func (c *Config) GetInt(section, key string, def int64) int64 {
	if v, ok := c.lookup(section, key); ok {
		if n, ok := v.(int64); ok {
			return n
		}
	}
	return def
}

// GetBool 返回布尔值；缺失或类型不符时返回 def。
func (c *Config) GetBool(section, key string, def bool) bool {
	if v, ok := c.lookup(section, key); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// GetStringSlice 返回字符串数组；缺失或类型不符时返回 def。
func (c *Config) GetStringSlice(section, key string, def []string) []string {
	if v, ok := c.lookup(section, key); ok {
		if s, ok := v.([]string); ok {
			return s
		}
	}
	return def
}

// GetIntSlice 返回整数数组；缺失或类型不符时返回 def。
func (c *Config) GetIntSlice(section, key string, def []int64) []int64 {
	if v, ok := c.lookup(section, key); ok {
		if s, ok := v.([]int64); ok {
			return s
		}
	}
	return def
}
