package util

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var defaultOutputFiles = []string{
	"error.txt",
	"flag.txt",
	"md5_horse_error.txt",
	"md5_horse_success.txt",
	"ssh_password_success.txt",
	"success.txt",
	"target.txt",
	"undead_horse_error.txt",
	"undead_horse_success.txt",
	"worm_paths.txt",
	"worm_paths_all.txt",
}

func ExeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func JoinExePath(parts ...string) string {
	segments := append([]string{ExeDir()}, parts...)
	return filepath.Join(segments...)
}

func OutputDir() string {
	return JoinExePath("output")
}

func LogDir() string {
	return JoinExePath("log")
}

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func EnsureDefaultOutputFiles() error {
	if err := EnsureDir(OutputDir()); err != nil {
		return err
	}
	for _, name := range defaultOutputFiles {
		full := filepath.Join(OutputDir(), name)
		if _, err := os.Stat(full); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(full, nil, 0o644); err != nil {
				return err
			}
		}
	}
	return EnsureDir(LogDir())
}

func WriteLinesAtomic(path string, lines []string) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + ".tmp"
	content := strings.Join(lines, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func AppendLines(path string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	return AppendText(path, strings.Join(lines, "\n"))
}

func AppendText(path, content string) error {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	return err
}

func ValidateIPAddress(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() != nil
}

func IsSubPath(root, path string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func UniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func ReadLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}
