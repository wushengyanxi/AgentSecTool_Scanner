package main

// 目标输入展开器：把单条「目标表达式」展开成一系列 IP，通过流式回调逐个交付，
// 避免大段展开（如双通配 256*256 或大 CIDR）一次性占用大量内存。
//
// 自动识别四种输入形式，判定顺序（先到先得）：
//  1. 文件路径：os.Stat 命中且为普通文件 → 逐行读，每行再次按本规则展开（# 注释、空行跳过）。
//  2. CIDR：含 '/' → net.ParseCIDR 展开为该网段全部地址。
//  3. 通配 IP：含 '*' → 每个 '*' 八位组枚举 0-255。
//  4. 精确 IP：以上都不是 → 当作单个 IP 校验后交付。
//
// 不设展开数量上限，调用方自负其责。

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ExpandTarget 把一条目标表达式展开为若干 IP，对每个 IP 调用 emit。
// emit 返回非 nil 错误会立即中止展开并把该错误原样返回，便于调用方提前停止。
func ExpandTarget(expr string, emit func(ip string) error) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty target expression")
	}

	switch {
	case isExistingFile(expr):
		return expandFile(expr, emit)
	case strings.Contains(expr, "/"):
		return expandCIDR(expr, emit)
	case strings.Contains(expr, "*"):
		return expandWildcard(expr, emit)
	default:
		return expandExact(expr, emit)
	}
}

// isExistingFile 报告 path 是否指向一个已存在的普通文件。
// 目录不算（避免把形如 "10.0.0.0" 这类恰好同名的目录误判为文件输入）。
func isExistingFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// expandFile 逐行读取文件，每行去掉首尾空白后：空行与 '#' 注释行跳过，
// 其余行作为新的目标表达式递归展开（支持文件内混写精确 IP / CIDR / 通配）。
func expandFile(path string, emit func(ip string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := ExpandTarget(line, emit); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// expandExact 校验单个精确 IP 并交付。仅接受 IPv4 字面量。
func expandExact(expr string, emit func(ip string) error) error {
	ip := net.ParseIP(expr)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IP address: %q", expr)
	}
	return emit(ip.To4().String())
}

// expandCIDR 用 net.ParseCIDR 解析 IPv4 网段，遍历该段全部地址（含网络号与广播号）。
func expandCIDR(expr string, emit func(ip string) error) error {
	_, ipnet, err := net.ParseCIDR(expr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %q: %w", expr, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR supported: %q", expr)
	}

	// 起始地址 = 网络号；逐个 +1 直到越出该网段范围（ipnet.Contains 负责边界）。
	cur := make(net.IP, len(ip4))
	copy(cur, ip4)
	for ipnet.Contains(cur) {
		if err := emit(cur.String()); err != nil {
			return err
		}
		if !incIP(cur) {
			break // 自增整体回绕（到 255.255.255.255 之后），结束。
		}
	}
	return nil
}

// incIP 把 ip 自增 1（大端，最低八位组进位）。若发生整体回绕（全 0xff → 全 0x00）返回 false。
func incIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

// expandWildcard 展开形如 "123.*.*.4" 的通配 IPv4：每个 '*' 八位组枚举 0-255，
// 固定八位组校验为合法 0-255。采用逐位回调，双通配也只占常数内存。
func expandWildcard(expr string, emit func(ip string) error) error {
	octets := strings.Split(expr, ".")
	if len(octets) != 4 {
		return fmt.Errorf("invalid wildcard IP (need 4 octets): %q", expr)
	}

	// 校验非通配位为合法八位组，记录哪些位是通配。
	fixed := make([]int, 4)   // 固定位的数值
	isStar := make([]bool, 4) // 是否通配
	for i, o := range octets {
		if o == "*" {
			isStar[i] = true
			continue
		}
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return fmt.Errorf("invalid octet %q in wildcard %q", o, expr)
		}
		fixed[i] = n
	}

	var parts [4]int
	var rec func(idx int) error
	rec = func(idx int) error {
		if idx == 4 {
			ip := fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], parts[2], parts[3])
			return emit(ip)
		}
		if !isStar[idx] {
			parts[idx] = fixed[idx]
			return rec(idx + 1)
		}
		for v := 0; v <= 255; v++ {
			parts[idx] = v
			if err := rec(idx + 1); err != nil {
				return err
			}
		}
		return nil
	}
	return rec(0)
}
