package main

import (
	"os"
	"path/filepath"
	"testing"
)

// collect 把 ExpandTarget 的流式回调收集成切片，便于断言。
func collect(t *testing.T, expr string) []string {
	t.Helper()
	var got []string
	if err := ExpandTarget(expr, func(ip string) error {
		got = append(got, ip)
		return nil
	}); err != nil {
		t.Fatalf("ExpandTarget(%q) unexpected error: %v", expr, err)
	}
	return got
}

func TestExpandExactIP(t *testing.T) {
	got := collect(t, "1.2.3.4")
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("exact IP: want [1.2.3.4], got %v", got)
	}
}

func TestExpandExactIPTrimsWhitespace(t *testing.T) {
	got := collect(t, "  10.0.0.1  ")
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("trimmed exact IP: want [10.0.0.1], got %v", got)
	}
}

func TestExpandCIDRSlash30(t *testing.T) {
	// /30 覆盖 4 个地址：网络号、两个主机、广播号，全部展开。
	got := collect(t, "203.0.113.0/30")
	want := []string{"203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"}
	if len(got) != len(want) {
		t.Fatalf("CIDR /30: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CIDR /30 at %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func TestExpandCIDRSlash31(t *testing.T) {
	got := collect(t, "192.168.1.4/31")
	want := []string{"192.168.1.4", "192.168.1.5"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("CIDR /31: want %v, got %v", want, got)
	}
}

func TestExpandCIDRSlash32(t *testing.T) {
	got := collect(t, "8.8.8.8/32")
	if len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("CIDR /32: want [8.8.8.8], got %v", got)
	}
}

func TestExpandCIDRNonNetworkBase(t *testing.T) {
	// ParseCIDR 会把基址归一到网络号；/30 从 .4 开始。
	got := collect(t, "10.1.1.6/30")
	want := []string{"10.1.1.4", "10.1.1.5", "10.1.1.6", "10.1.1.7"}
	if len(got) != len(want) {
		t.Fatalf("CIDR non-network base: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func TestExpandWildcardSingleStar(t *testing.T) {
	// 123.0.*.4 → 枚举第三段 0-255，共 256 个。
	got := collect(t, "123.0.*.4")
	if len(got) != 256 {
		t.Fatalf("single-star wildcard: want 256 results, got %d", len(got))
	}
	if got[0] != "123.0.0.4" {
		t.Fatalf("first result: want 123.0.0.4, got %s", got[0])
	}
	if got[255] != "123.0.255.4" {
		t.Fatalf("last result: want 123.0.255.4, got %s", got[255])
	}
	if got[100] != "123.0.100.4" {
		t.Fatalf("100th result: want 123.0.100.4, got %s", got[100])
	}
}

func TestExpandWildcardDoubleStar(t *testing.T) {
	// 两个 * → 256*256 = 65536，验证流式展开数量正确。
	count := 0
	var first, last string
	err := ExpandTarget("10.*.*.1", func(ip string) error {
		if count == 0 {
			first = ip
		}
		last = ip
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("double-star wildcard error: %v", err)
	}
	if count != 256*256 {
		t.Fatalf("double-star count: want %d, got %d", 256*256, count)
	}
	if first != "10.0.0.1" {
		t.Fatalf("double-star first: want 10.0.0.1, got %s", first)
	}
	if last != "10.255.255.1" {
		t.Fatalf("double-star last: want 10.255.255.1, got %s", last)
	}
}

func TestExpandFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "" +
		"# 注释行应被跳过\n" +
		"1.1.1.1\n" +
		"\n" + // 空行跳过
		"   2.2.2.2   \n" + // 带空白
		"   # 缩进注释也跳过\n" +
		"203.0.113.0/30\n" + // 文件内混写 CIDR
		"9.9.9.*\n" // 文件内混写通配（不验全部，仅验数量）

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got := collect(t, path)
	// 期望：1.1.1.1, 2.2.2.2, 四个 /30 地址, 256 个通配 = 2 + 4 + 256 = 262
	if len(got) != 262 {
		t.Fatalf("file expansion count: want 262, got %d (%v...)", len(got), got[:min(len(got), 8)])
	}
	if got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("file first two: want [1.1.1.1 2.2.2.2], got %v", got[:2])
	}
	if got[2] != "203.0.113.0" || got[5] != "203.0.113.3" {
		t.Fatalf("file CIDR block: got %v", got[2:6])
	}
}

func TestExpandFilePriorityOverIP(t *testing.T) {
	// 文件判定优先级最高：即便文件名长得不像 IP，存在即按文件读。
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.lst")
	if err := os.WriteFile(path, []byte("5.5.5.5\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := collect(t, path)
	if len(got) != 1 || got[0] != "5.5.5.5" {
		t.Fatalf("file-over-ip: want [5.5.5.5], got %v", got)
	}
}

func TestExpandCandidatesCSVUsesFirstColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidates.csv")
	content := "" +
		"1.1.1.1,18789\n" +
		"203.0.113.0/31,18789\n" +
		"  8.8.8.8  , 443\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := collect(t, path)
	want := []string{"1.1.1.1", "203.0.113.0", "203.0.113.1", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("csv expansion count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("csv expansion at %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func TestExpandErrors(t *testing.T) {
	cases := []string{
		"",              // 空表达式
		"   ",           // 仅空白
		"999.1.1.1",     // 越界八位组（精确 IP）
		"1.2.3",         // 段数不足（既非文件也非 CIDR/通配）
		"not-an-ip",     // 垃圾输入
		"1.2.3.4/33",    // 非法 CIDR 掩码
		"1.2.3.4/abc",   // 非法 CIDR
		"300.*.1.1",     // 通配中固定位越界
		"1.*.1",         // 通配段数不足
		"1.2.3.4.5",     // 段数过多
		"::1",           // IPv6 精确 IP（仅支持 IPv4）
		"2001:db8::/32", // IPv6 CIDR（仅支持 IPv4）
	}
	for _, c := range cases {
		err := ExpandTarget(c, func(string) error { return nil })
		if err == nil {
			t.Errorf("ExpandTarget(%q): expected error, got nil", c)
		}
	}
}

func TestEmitErrorAborts(t *testing.T) {
	// emit 返回错误应立即中止并原样返回该错误。
	sentinel := os.ErrClosed
	count := 0
	err := ExpandTarget("10.0.0.*", func(string) error {
		count++
		if count == 3 {
			return sentinel
		}
		return nil
	})
	if err != sentinel {
		t.Fatalf("emit-error: want sentinel, got %v", err)
	}
	if count != 3 {
		t.Fatalf("emit-error: want aborted at 3, got %d emits", count)
	}
}
