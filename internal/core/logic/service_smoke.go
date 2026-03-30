package logic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"awd-h1m-pro/internal/util"
)

type fileSnapshot struct {
	path   string
	exists bool
	data   []byte
}

// ============================================
// [已停用-UI已移除] 自检功能
// 保留后端代码供开发调试使用
// 如需恢复UI，取消下方注释即可
// ============================================
func (s *ServiceService) RunIntegrationSmoke(progress func(SmokeProgressEvent)) (*SmokeReport, error) {
	report := &SmokeReport{
		StartedAt: time.Now(),
		Status:    "running",
	}
	configPath := util.JoinExePath("config.yaml")
	targetPath := filepath.Join(util.OutputDir(), "target.txt")
	snapshots, err := snapshotFiles(configPath, targetPath)
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
		s.storeSmokeReport(report)
		return report, err
	}
	defer restoreSnapshots(snapshots)

	helperPath, buildErr := ensureSmokeHelper(progress)
	if buildErr != nil {
		report.Status = "error"
		report.Error = buildErr.Error()
		report.FinishedAt = time.Now()
		report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
		s.storeSmokeReport(report)
		return report, buildErr
	}

	cmd := exec.Command(helperPath)
	cmd.Dir = util.ExeDir()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
		s.storeSmokeReport(report)
		return report, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
		s.storeSmokeReport(report)
		return report, err
	}
	if err := cmd.Start(); err != nil {
		report.Status = "error"
		report.Error = err.Error()
		s.storeSmokeReport(report)
		return report, err
	}

	var (
		stdoutBuf  bytes.Buffer
		progressMu sync.Mutex
		wg         sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stdoutBuf, stdoutPipe)
	}()
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			event := parseSmokeProgressLine(scanner.Text())
			progressMu.Lock()
			report.Progress = append(report.Progress, event)
			progressMu.Unlock()
			if progress != nil {
				progress(event)
			}
		}
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	output := strings.TrimSpace(stdoutBuf.String())
	if output != "" {
		if err := json.Unmarshal([]byte(output), &report.Results); err != nil {
			report.Status = "error"
			report.Error = fmt.Sprintf("parse smoke result failed: %v", err)
			report.FinishedAt = time.Now()
			report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
			s.storeSmokeReport(report)
			return report, fmt.Errorf("%s", report.Error)
		}
	}
	for _, item := range report.Results {
		if item.Success {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	report.FinishedAt = time.Now()
	report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
	switch {
	case waitErr != nil && report.Failed == 0:
		report.Status = "error"
		report.Error = waitErr.Error()
	case report.Failed > 0:
		report.Status = "failed"
		if waitErr != nil {
			report.Error = waitErr.Error()
		}
	default:
		report.Status = "passed"
	}
	s.storeSmokeReport(report)
	if waitErr != nil && report.Failed == 0 {
		return report, waitErr
	}
	return report, nil
}

func (s *ServiceService) GetLatestSmokeReport() *SmokeReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestSmoke == nil {
		return nil
	}
	copyValue := *s.latestSmoke
	copyValue.Results = append([]SmokeCheckResult(nil), s.latestSmoke.Results...)
	copyValue.Progress = append([]SmokeProgressEvent(nil), s.latestSmoke.Progress...)
	return &copyValue
}

func (s *ServiceService) storeSmokeReport(report *SmokeReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latestSmoke = report
}

func ensureSmokeHelper(progress func(SmokeProgressEvent)) (string, error) {
	helperPath := util.JoinExePath("integration-smoke.exe")
	repoRoot := findSmokeProjectRoot()
	if repoRoot == "" {
		if _, err := os.Stat(helperPath); err == nil {
			emitSmokeProgress(progress, "smoke.build", "warning", "source tree not found, using existing integration-smoke.exe")
			return helperPath, nil
		}
		return "", fmt.Errorf("cannot locate project root for cmd/integration-smoke")
	}

	build := exec.Command("go", "build", "-o", helperPath, "./cmd/integration-smoke")
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		if _, statErr := os.Stat(helperPath); statErr == nil {
			emitSmokeProgress(progress, "smoke.build", "warning", strings.TrimSpace(string(output)))
			return helperPath, nil
		}
		return "", fmt.Errorf("build integration-smoke failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	emitSmokeProgress(progress, "smoke.build", "done", "integration-smoke.exe rebuilt")
	return helperPath, nil
}

func findSmokeProjectRoot() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	candidates = append(candidates, util.ExeDir(), filepath.Dir(util.ExeDir()))
	seen := make(map[string]struct{})
	for _, base := range candidates {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		for dir := base; dir != "" && dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			if _, ok := seen[dir]; ok {
				continue
			}
			seen[dir] = struct{}{}
			if fileExists(filepath.Join(dir, "go.mod")) && fileExists(filepath.Join(dir, "cmd", "integration-smoke", "main.go")) {
				return dir
			}
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func snapshotFiles(paths ...string) ([]fileSnapshot, error) {
	snapshots := make([]fileSnapshot, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				snapshots = append(snapshots, fileSnapshot{path: path, exists: false})
				continue
			}
			return nil, err
		}
		snapshots = append(snapshots, fileSnapshot{path: path, exists: true, data: append([]byte(nil), data...)})
	}
	return snapshots, nil
}

func restoreSnapshots(snapshots []fileSnapshot) {
	for _, snapshot := range snapshots {
		if !snapshot.exists {
			_ = os.Remove(snapshot.path)
			continue
		}
		if err := util.EnsureDir(filepath.Dir(snapshot.path)); err != nil {
			continue
		}
		_ = os.WriteFile(snapshot.path, snapshot.data, 0o644)
	}
}

func parseSmokeProgressLine(line string) SmokeProgressEvent {
	event := SmokeProgressEvent{
		Timestamp: time.Now(),
		Stage:     "smoke",
		Status:    "info",
		Detail:    strings.TrimSpace(line),
		Line:      strings.TrimSpace(line),
	}
	trimmed := strings.TrimSpace(strings.TrimPrefix(line, "[smoke]"))
	switch {
	case strings.HasPrefix(trimmed, "start "):
		event.Status = "running"
		event.Stage = strings.TrimSpace(strings.TrimPrefix(trimmed, "start "))
	case strings.HasPrefix(trimmed, "pass"):
		event.Status = "done"
		event.Stage = strings.TrimSpace(strings.TrimPrefix(trimmed, "pass"))
	case strings.HasPrefix(trimmed, "fail"):
		event.Status = "failed"
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "fail"))
		stage, detail, ok := strings.Cut(rest, ":")
		if ok {
			event.Stage = strings.TrimSpace(stage)
			event.Detail = strings.TrimSpace(detail)
		} else {
			event.Stage = rest
		}
	}
	return event
}

func emitSmokeProgress(progress func(SmokeProgressEvent), stage, status, detail string) {
	if progress == nil {
		return
	}
	progress(SmokeProgressEvent{
		Timestamp: time.Now(),
		Stage:     stage,
		Status:    status,
		Detail:    detail,
		Line:      detail,
	})
}
