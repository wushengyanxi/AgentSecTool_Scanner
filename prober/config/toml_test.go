package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEmpty(t *testing.T) {
	cfg, err := Parse([]byte(""))
	if err != nil {
		t.Fatalf("空文件不应报错，got %v", err)
	}
	if len(cfg.Sections()) != 1 {
		t.Fatalf("空文件应只有默认段，got %v", cfg.Sections())
	}
	if _, ok := cfg.Sections()[""]; !ok {
		t.Fatalf("应存在默认段 \"\"")
	}
}

func TestParseCommentsAndBlankLines(t *testing.T) {
	in := `
# 这是一行注释

# 又一行
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("纯注释/空行不应报错，got %v", err)
	}
	if got := len(cfg.Sections()[""]); got != 0 {
		t.Fatalf("默认段不应有键，got %d 个", got)
	}
}

func TestParseScalars(t *testing.T) {
	in := `
[server]
host = "127.0.0.1"   # 行内注释应被忽略
port = 8080
enabled = true
debug = false
neg = -42
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if got := cfg.GetString("server", "host", "x"); got != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", got)
	}
	if got := cfg.GetInt("server", "port", 0); got != 8080 {
		t.Errorf("port = %d, want 8080", got)
	}
	if got := cfg.GetBool("server", "enabled", false); got != true {
		t.Errorf("enabled = %v, want true", got)
	}
	if got := cfg.GetBool("server", "debug", true); got != false {
		t.Errorf("debug = %v, want false", got)
	}
	if got := cfg.GetInt("server", "neg", 0); got != -42 {
		t.Errorf("neg = %d, want -42", got)
	}
}

func TestParseHashInsideString(t *testing.T) {
	in := `key = "a#b#c"`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := cfg.GetString("", "key", ""); got != "a#b#c" {
		t.Errorf("引号内的 # 不应被当注释，got %q", got)
	}
}

func TestParseStringArray(t *testing.T) {
	in := `tags = ["a", "b", "c"]`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []string{"a", "b", "c"}
	if got := cfg.GetStringSlice("", "tags", nil); !reflect.DeepEqual(got, want) {
		t.Errorf("tags = %v, want %v", got, want)
	}
}

func TestParseIntArray(t *testing.T) {
	in := `ports = [80, 443, 8080]`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []int64{80, 443, 8080}
	if got := cfg.GetIntSlice("", "ports", nil); !reflect.DeepEqual(got, want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
}

func TestParseEmptyArray(t *testing.T) {
	cfg, err := Parse([]byte(`x = []`))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := cfg.GetStringSlice("", "x", nil); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("空数组应为 []string{}，got %#v", got)
	}
}

func TestArrayWithCommaInString(t *testing.T) {
	in := `csv = ["a,b", "c"]`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []string{"a,b", "c"}
	if got := cfg.GetStringSlice("", "csv", nil); !reflect.DeepEqual(got, want) {
		t.Errorf("csv = %v, want %v", got, want)
	}
}

func TestMultipleSections(t *testing.T) {
	in := `
key0 = "top"

[a]
x = 1

[b]
x = 2
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := cfg.GetString("", "key0", ""); got != "top" {
		t.Errorf("段外 key0 = %q, want top", got)
	}
	if got := cfg.GetInt("a", "x", 0); got != 1 {
		t.Errorf("a.x = %d, want 1", got)
	}
	if got := cfg.GetInt("b", "x", 0); got != 2 {
		t.Errorf("b.x = %d, want 2", got)
	}
}

func TestDefaultsOnMissing(t *testing.T) {
	cfg, _ := Parse([]byte(`[s]` + "\nk = 1\n"))
	if got := cfg.GetString("s", "nope", "def"); got != "def" {
		t.Errorf("缺失键应返回 def，got %q", got)
	}
	if got := cfg.GetInt("nope", "k", 99); got != 99 {
		t.Errorf("缺失段应返回 def，got %d", got)
	}
	// 类型不符也应回退到 def
	if got := cfg.GetString("s", "k", "def"); got != "def" {
		t.Errorf("类型不符应返回 def，got %q", got)
	}
}

func TestInvalidLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // 期望 error 文本里包含的片段
	}{
		{"缺少等号", "justakey", "缺少 '='"},
		{"键为空", "= 1", "键为空"},
		{"值为空", "k =", "值为空"},
		{"段未闭合", "[oops", "缺少闭合的 ']'"},
		{"段名为空", "[]", "section 名为空"},
		{"字符串未闭合", `k = "abc`, "闭合引号"},
		{"无法识别的值", "k = 1.5", "无法识别的值"},
		{"数组未闭合", "k = [1, 2", "缺少闭合的 ']'"},
		{"数组类型混合", `k = ["a", 1]`, "类型不一致"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil {
				t.Fatalf("期望报错，但解析成功")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, 期望包含 %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "line ") {
				t.Errorf("error 应包含行号，got %q", err.Error())
			}
		})
	}
}

func TestErrorLineNumber(t *testing.T) {
	in := "ok = 1\n# comment\nbad line here\n"
	_, err := Parse([]byte(in))
	if err == nil {
		t.Fatal("期望报错")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("应指出第 3 行，got %q", err.Error())
	}
}
