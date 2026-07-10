package targeting

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ExpandTarget expands a target expression into IP addresses and streams them
// through emit. Supported forms: file path, "-", CIDR, wildcard IPv4, exact IPv4.
func ExpandTarget(expr string, emit func(ip string) error) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty target expression")
	}

	switch {
	case expr == "-":
		return expandReader(os.Stdin, emit)
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

func isExistingFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func expandFile(path string, emit func(ip string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return expandReader(f, emit)
}

func expandReader(f *os.File, emit func(ip string) error) error {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept candidates.csv rows by taking the first column. A plain target
		// file remains unchanged because lines without commas pass through.
		if i := strings.IndexByte(line, ','); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if err := ExpandTarget(line, emit); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func expandExact(expr string, emit func(ip string) error) error {
	ip := net.ParseIP(expr)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IP address: %q", expr)
	}
	return emit(ip.To4().String())
}

func expandCIDR(expr string, emit func(ip string) error) error {
	_, ipnet, err := net.ParseCIDR(expr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %q: %w", expr, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR supported: %q", expr)
	}

	cur := make(net.IP, len(ip4))
	copy(cur, ip4)
	for ipnet.Contains(cur) {
		if err := emit(cur.String()); err != nil {
			return err
		}
		if !incIP(cur) {
			break
		}
	}
	return nil
}

func incIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

func expandWildcard(expr string, emit func(ip string) error) error {
	octets := strings.Split(expr, ".")
	if len(octets) != 4 {
		return fmt.Errorf("invalid wildcard IP (need 4 octets): %q", expr)
	}

	fixed := make([]int, 4)
	isStar := make([]bool, 4)
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
