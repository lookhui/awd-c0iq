package logic

import (
	"fmt"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/util"
)

var taskCounter atomic.Uint64

func nextTaskID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().Unix(), taskCounter.Add(1))
}

func buildURL(target string) string {
	cfg := config.Clone()
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return buildURLForTargetPath(target, remoteJoin(cfg.Shell.Path, cfg.Shell.File))
}

func buildURLWithQuery(raw string, query map[string]string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	values := parsed.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func buildURLForTargetPath(target, remotePath string) string {
	cfg := config.Clone()
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if remotePath == "" {
			return target
		}
		if parsed, err := url.Parse(target); err == nil {
			parsed.Path = ensureRemotePath(remotePath)
			return parsed.String()
		}
		return target
	}
	base := fmt.Sprintf("http://%s", target)
	if cfg.Shell.Port != "" && cfg.Shell.Port != "80" {
		base = fmt.Sprintf("http://%s:%s", target, cfg.Shell.Port)
	}
	return strings.TrimRight(base, "/") + ensureRemotePath(remotePath)
}

func ensureRemotePath(remotePath string) string {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return "/"
	}
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	return pathpkg.Clean(remotePath)
}

func remoteJoin(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		filtered = append(filtered, part)
	}
	if len(filtered) == 0 {
		return "/"
	}
	joined := pathpkg.Join(filtered...)
	if strings.HasPrefix(filtered[0], "/") && !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

func ParseTargetsInput(input string) []string {
	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	var targets []string
	for _, line := range lines {
		targets = append(targets, ParseLineToTargets(line)...)
	}
	return util.UniqueSorted(targets)
}

func ParseLineToTargets(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if !strings.Contains(line, "-") {
		return []string{line}
	}
	return ParseIPRange(line)
}

func ParseIPRange(raw string) []string {
	if !strings.Contains(raw, "-") {
		return []string{strings.TrimSpace(raw)}
	}
	result := ExpandIPRange(raw)
	if len(result) == 0 {
		return []string{strings.TrimSpace(raw)}
	}
	return result
}

func ExpandIPRange(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), "-")
	if len(parts) != 2 {
		return nil
	}
	start := strings.TrimSpace(parts[0])
	endRaw := strings.TrimSpace(parts[1])
	ip := net.ParseIP(start)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	octets := strings.Split(start, ".")
	if len(octets) != 4 {
		return nil
	}
	startLast, err := strconv.Atoi(octets[3])
	if err != nil {
		return nil
	}
	endLast, err := strconv.Atoi(endRaw)
	if err != nil {
		if ip2 := net.ParseIP(endRaw); ip2 != nil && ip2.To4() != nil {
			endOctets := strings.Split(endRaw, ".")
			if len(endOctets) != 4 || strings.Join(endOctets[:3], ".") != strings.Join(octets[:3], ".") {
				return nil
			}
			endLast, err = strconv.Atoi(endOctets[3])
			if err != nil {
				return nil
			}
		} else {
			return nil
		}
	}
	if endLast < startLast || endLast > 255 {
		return nil
	}
	prefix := strings.Join(octets[:3], ".")
	result := make([]string, 0, endLast-startLast+1)
	for i := startLast; i <= endLast; i++ {
		result = append(result, fmt.Sprintf("%s.%d", prefix, i))
	}
	return result
}

func LoadTargetsFromOutput() ([]string, error) {
	targetFile := filepath.Join(util.OutputDir(), "target.txt")
	if _, err := os.Stat(targetFile); err == nil {
		return util.ReadLines(targetFile)
	}
	cfg := config.Clone()
	if strings.TrimSpace(cfg.SSH.Host) != "" {
		return []string{strings.TrimSpace(cfg.SSH.Host)}, nil
	}
	return nil, nil
}
