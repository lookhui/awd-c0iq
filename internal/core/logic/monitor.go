package logic

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/util"
)

func NewMonitorService(sshService *ServiceService) *MonitorService {
	return &MonitorService{
		stopChan:     make(chan bool),
		captureStop:  make(map[string]func()),
		captureHosts: make(map[string]map[string]struct{}),
		captureHTTP:  make(map[string]*liveHTTPStream),
		sessions:     make(map[string]*RemoteCaptureSession),
		sshService:   sshService,
	}
}

func (s *MonitorService) StartLocalMonitor(path string) {
	go s.runMonitorLoop(path)
}

func createInitialSnapshot(root string) map[string]FileMonitor {
	snapshot := make(map[string]FileMonitor)
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		hash, _ := fileHash(path)
		snapshot[path] = FileMonitor{
			Path:         path,
			LastModified: info.ModTime(),
			Size:         info.Size(),
			Hash:         hash,
		}
		return nil
	})
	return snapshot
}

func (s *MonitorService) runMonitorLoop(root string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	last := createInitialSnapshot(root)
	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			last = checkAndUpdateFiles(root, last)
		}
	}
}

func checkAndUpdateFiles(root string, last map[string]FileMonitor) map[string]FileMonitor {
	current := createInitialSnapshot(root)
	detectFileChanges(last, current)
	return current
}

func detectFileChanges(last, current map[string]FileMonitor) {
	detectNewAndModifiedFiles(last, current)
	detectDeletedFiles(last, current)
}

func detectNewAndModifiedFiles(last, current map[string]FileMonitor) {
	for path, cur := range current {
		old, ok := last[path]
		switch {
		case !ok:
			logFileChange("created", path)
		case old.Hash != cur.Hash || old.Size != cur.Size || !old.LastModified.Equal(cur.LastModified):
			logFileChange("modified", path)
		}
	}
}

func detectDeletedFiles(last, current map[string]FileMonitor) {
	for path := range last {
		if _, ok := current[path]; !ok {
			logFileChange("deleted", path)
		}
	}
}

func (s *MonitorService) StopMonitor() {
	select {
	case s.stopChan <- true:
	default:
	}
}

func logFileChange(action, path string) {
	logger.Warning("file change detected", "action", action, "path", path)
	writeLogEntry(formatLogEntry(action, path))
}

func ensureLogDir() error {
	return util.EnsureDir(util.LogDir())
}

func getLogFilePath() string {
	return filepath.Join(util.LogDir(), "monitor.log")
}

func writeLogEntry(entry string) {
	if err := ensureLogDir(); err != nil {
		return
	}
	file, err := os.OpenFile(getLogFilePath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(entry + "\n")
}

func formatLogEntry(action, path string) string {
	return time.Now().Format(time.RFC3339) + " " + action + " " + path
}

func MonitorLogs(path string) {
	file, err := openLogFile(path)
	if err != nil {
		return
	}
	defer file.Close()
	runLogMonitorLoop(file)
}

func openLogFile(path string) (*os.File, error) {
	return os.Open(path)
}

func runLogMonitorLoop(file *os.File) {
	for {
		time.Sleep(5 * time.Second)
		if _, err := file.Seek(0, 0); err != nil {
			return
		}
		content, err := os.ReadFile(file.Name())
		if err != nil {
			return
		}
		readAndAnalyzeNewContent(string(content))
	}
}

func readAndAnalyzeNewContent(content string) {
	analyzeLog(content)
}

func analyzeLog(content string) {
	lower := strings.ToLower(content)
	for _, keyword := range []string{"eval(", "assert(", "system(", "base64_decode", "shell_exec"} {
		if strings.Contains(lower, keyword) {
			logger.Warning("suspicious log content", "keyword", keyword)
		}
	}
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:]), nil
}
