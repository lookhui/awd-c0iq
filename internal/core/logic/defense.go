package logic

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/util"

	"golang.org/x/crypto/ssh"
)

func NewDefenseService(sshService *ServiceService) *DefenseService {
	return &DefenseService{
		knownHosts: make(map[string]string),
		sshService: sshService,
	}
}

func (s *DefenseService) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	_ = remote
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knownHosts[hostname] = ssh.FingerprintSHA256(key)
	return nil
}

func (s *DefenseService) validateSSHConfig() error {
	cfg := config.Clone()
	if strings.TrimSpace(cfg.SSH.Username) == "" || strings.TrimSpace(cfg.SSH.Password) == "" {
		return fmt.Errorf("ssh username/password is empty")
	}
	if strings.TrimSpace(cfg.SSH.Port) == "" {
		cfg.SSH.Port = "22"
	}
	if strings.TrimSpace(cfg.SSH.Path) == "" {
		cfg.SSH.Path = "/var/www/html"
	}
	return nil
}

func (s *DefenseService) validateSSHConfigForScan() error {
	return s.validateSSHConfig()
}

func shellQuote(value string) string {
	value = strings.ReplaceAll(value, `'`, `'\''`)
	return "'" + value + "'"
}

func (s *DefenseService) createSSHClient(host string) (sshClientHandle, error) {
	if client, ok := s.sshService.borrowSSHClientForHost(host); ok {
		return sshClientHandle{client: client, shared: true}, nil
	}
	if err := s.validateSSHConfig(); err != nil {
		return sshClientHandle{}, err
	}
	cfg := config.Clone()
	clientCfg := &ssh.ClientConfig{
		User:            cfg.SSH.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.SSH.Password)},
		HostKeyCallback: s.hostKeyCallback,
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, cfg.SSH.Port), clientCfg)
	if err != nil {
		return sshClientHandle{}, err
	}
	return sshClientHandle{client: client}, nil
}

func (s *DefenseService) createSSHClientForScan(host string) (sshClientHandle, error) {
	return s.createSSHClient(host)
}

func parseMyIPs(input string) []string {
	parts := strings.Split(input, ",")
	ips := make([]string, 0, len(parts))
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return util.UniqueSorted(ips)
}

func resolveDefenseTargets(targetsInput string, sshService *ServiceService) ([]string, error) {
	targets := parseMyIPs(targetsInput)
	if len(targets) == 0 {
		if host := resolveActiveSSHHost(sshService); host != "" {
			targets = []string{host}
		}
	}
	if len(targets) == 0 {
		targets = parseMyIPs(config.Clone().OwnIPs)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("own IPs are empty")
	}
	return targets, nil
}

func (s *DefenseService) BackupWebRoot(targetsInput string) ([]string, error) {
	targets, err := resolveDefenseTargets(targetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found")
	}
	results := make([]string, 0, len(targets))
	for _, target := range targets {
		backup, backupErr := s.executeBackup(target)
		if backupErr != nil {
			results = append(results, fmt.Sprintf("%s backup failed: %v", target, backupErr))
			continue
		}
		results = append(results, backup)
	}
	return results, nil
}

func (s *DefenseService) executeBackup(target string) (string, error) {
	client, err := s.createSSHClient(target)
	if err != nil {
		return "", err
	}
	defer client.Close()
	cfg := config.Clone()
	remotePath := fmt.Sprintf("/tmp/webroot_%s_%d.tar.gz", strings.ReplaceAll(target, ".", "_"), time.Now().Unix())
	command := fmt.Sprintf("tar -czf %s -C %s .", shellQuote(remotePath), shellQuote(cfg.SSH.Path))
	if _, err := runSSHCommand(client.Client(), command); err != nil {
		return "", err
	}
	return s.downloadFileToSubdir(client.Client(), remotePath, target, "web")
}

func (s *DefenseService) downloadFileToSubdir(client *ssh.Client, remotePath, target, subdir string) (string, error) {
	output, err := runSSHCommand(client, fmt.Sprintf("base64 < %s | tr -d '\n'", shellQuote(remotePath)))
	if err != nil {
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		return "", err
	}
	dir := filepath.Join(util.OutputDir(), "backup", subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	localPath := filepath.Join(dir, filepath.Base(remotePath)+"_"+strings.ReplaceAll(target, ":", "_"))
	if err := os.WriteFile(localPath, decoded, 0o644); err != nil {
		return "", err
	}
	return localPath, nil
}

func (s *DefenseService) BackupDatabase(targetsInput string) ([]string, error) {
	targets, err := resolveDefenseTargets(targetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(targets))
	cfg := config.Clone()
	for _, target := range targets {
		client, connErr := s.createSSHClient(target)
		if connErr != nil {
			results = append(results, fmt.Sprintf("%s connect failed: %v", target, connErr))
			continue
		}
		remotePath := fmt.Sprintf("/tmp/db_%s_%d.sql.gz", strings.ReplaceAll(target, ".", "_"), time.Now().Unix())
		command := fmt.Sprintf("mysqldump -h %s -P %s -u %s -p%s %s | gzip -c > %s",
			shellQuote(cfg.Database.Host),
			shellQuote(cfg.Database.Port),
			shellQuote(cfg.Database.Username),
			shellQuote(cfg.Database.Password),
			shellQuote(cfg.Database.Name),
			shellQuote(remotePath),
		)
		if _, err := runSSHCommand(client.Client(), command); err != nil {
			results = append(results, fmt.Sprintf("%s db backup failed: %v", target, err))
			_ = client.Close()
			continue
		}
		localPath, err := s.downloadFileToSubdir(client.Client(), remotePath, target, "db")
		_ = client.Close()
		if err != nil {
			results = append(results, fmt.Sprintf("%s db download failed: %v", target, err))
			continue
		}
		results = append(results, localPath)
	}
	return results, nil
}

func (s *DefenseService) ChangeDatabasePassword(targetsInput, newPassword string) ([]string, error) {
	targets, err := resolveDefenseTargets(targetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	cfg := config.Clone()
	results := make([]string, 0, len(targets))
	command := fmt.Sprintf(`mysql -h %s -P %s -u %s -p%s -e "ALTER USER '%s'@'%%' IDENTIFIED BY '%s'; FLUSH PRIVILEGES;"`,
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Username, cfg.Database.Password, cfg.Database.Username, newPassword)
	for _, target := range targets {
		client, connErr := s.createSSHClient(target)
		if connErr != nil {
			results = append(results, fmt.Sprintf("%s connect failed: %v", target, connErr))
			continue
		}
		_, cmdErr := runSSHCommand(client.Client(), command)
		_ = client.Close()
		if cmdErr != nil {
			results = append(results, fmt.Sprintf("%s db password failed: %v", target, cmdErr))
			continue
		}
		results = append(results, fmt.Sprintf("%s db password changed", target))
	}
	_ = config.Update(func(cfg *config.Config) {
		cfg.Database.Password = newPassword
	})
	return results, nil
}

func (s *DefenseService) uploadFileToRemote(client *ssh.Client, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	command := fmt.Sprintf("mkdir -p %s && base64 -d > %s", shellQuote(pathpkg.Dir(remotePath)), shellQuote(remotePath))
	return runSSHCommandWithInput(client, command, encoded)
}

func resolveBackupPath(path string) string {
	return filepath.Clean(path)
}

func (s *DefenseService) FindShells(targetsInput string) ([]ShellFinding, error) {
	targets, err := resolveDefenseTargets(targetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	findings := make([]ShellFinding, 0)
	for _, target := range targets {
		client, connErr := s.createSSHClientForScan(target)
		if connErr != nil {
			findings = append(findings, ShellFinding{Target: target, Reason: connErr.Error()})
			continue
		}
		output, scanErr := s.searchSuspiciousFiles(client.Client())
		_ = client.Close()
		if scanErr != nil {
			findings = append(findings, ShellFinding{Target: target, Reason: scanErr.Error()})
			continue
		}
		findings = append(findings, parseShellResults(target, output)...)
	}
	return findings, nil
}

func (s *DefenseService) HardenWebRoot(targetsInput string) ([]string, error) {
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		cfg := config.Clone()
		command := fmt.Sprintf("find %s -type d -exec chmod 755 {} + && find %s -type f -exec chmod 644 {} +",
			shellQuote(cfg.SSH.Path), shellQuote(cfg.SSH.Path))
		_, err := runSSHCommand(client, command)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s web root hardened", target), nil
	})
}

func (s *DefenseService) MakeUploadDirsReadOnly(targetsInput string) ([]string, error) {
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		cfg := config.Clone()
		command := fmt.Sprintf(`for dir in upload uploads Upload Uploads cache tmp temp; do
  if [ -d %s/$dir ]; then chmod -R 0555 %s/$dir; fi
done`, shellQuote(cfg.SSH.Path), shellQuote(cfg.SSH.Path))
		_, err := runSSHCommand(client, command)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s upload dirs hardened", target), nil
	})
}

func (s *DefenseService) HardenPHPConfig(targetsInput string) ([]string, error) {
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		cfg := config.Clone()
		remoteINI := remoteJoin(cfg.SSH.Path, ".user.ini")
		command := fmt.Sprintf("printf %s > %s", shellQuote("disable_functions=system,exec,shell_exec,passthru,proc_open,popen,assert\n"), shellQuote(remoteINI))
		_, err := runSSHCommand(client, command)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s php config hardened", target), nil
	})
}

func (s *DefenseService) DeploySimpleWAF(targetsInput string) ([]string, error) {
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		cfg := config.Clone()
		wafCode := `<?php
$body = file_get_contents("php://input");
$query = $_SERVER["QUERY_STRING"] ?? "";
$haystack = strtolower($query . "\n" . $body);
$deny = ["base64_decode", "assert(", "eval(", "shell_exec", "system(", "passthru("];
foreach ($deny as $item) {
    if (strpos($haystack, $item) !== false) {
        http_response_code(403);
        exit("blocked");
    }
}
?>`
		localTmp := filepath.Join(os.TempDir(), "awd-waf.php")
		if err := os.WriteFile(localTmp, []byte(wafCode), 0o644); err != nil {
			return "", err
		}
		defer os.Remove(localTmp)
		remoteWAF := remoteJoin(cfg.SSH.Path, "waf.php")
		remoteINI := remoteJoin(cfg.SSH.Path, ".user.ini")
		if err := s.uploadFileToRemote(client, localTmp, remoteWAF); err != nil {
			return "", err
		}
		iniContent := fmt.Sprintf("auto_prepend_file=%s\n", remoteWAF)
		_, err := runSSHCommand(client, fmt.Sprintf("printf %s > %s", shellQuote(iniContent), shellQuote(remoteINI)))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s waf deployed", target), nil
	})
}

func (s *DefenseService) InspectHost(targetsInput string) ([]string, error) {
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		output, err := runSSHCommand(client, "hostname; whoami; uname -a; id; ps aux | head -20; netstat -tunlp 2>/dev/null | head -20; crontab -l 2>/dev/null")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("[%s]\n%s", target, strings.TrimSpace(output)), nil
	})
}

func (s *DefenseService) searchSuspiciousFiles(client *ssh.Client) (string, error) {
	cfg := config.Clone()
	command := fmt.Sprintf(`find %s -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \) -exec grep -nH -E "eval\(|assert\(|base64_decode|system\(|shell_exec|passthru\(|preg_replace.*/e" {} + 2>/dev/null`, shellQuote(cfg.SSH.Path))
	return runSSHCommand(client, command)
}

func parseShellResults(target, output string) []ShellFinding {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	findings := make([]ShellFinding, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path := line
		reason := "suspicious pattern"
		if parts := strings.SplitN(line, ":", 3); len(parts) >= 2 {
			path = parts[0]
			if len(parts) == 3 {
				reason = parts[2]
			}
		}
		findings = append(findings, ShellFinding{Target: target, Path: path, Reason: reason})
	}
	return findings
}

func (s *DefenseService) RestoreWebFromBackup(targetsInput, localPath string) ([]string, error) {
	localPath = resolveBackupPath(localPath)
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		remotePath := fmt.Sprintf("/tmp/%s", filepath.Base(localPath))
		if err := s.uploadFileToRemote(client, localPath, remotePath); err != nil {
			return "", err
		}
		cfg := config.Clone()
		command := fmt.Sprintf("mkdir -p %s && tar -xzf %s -C %s", shellQuote(cfg.SSH.Path), shellQuote(remotePath), shellQuote(cfg.SSH.Path))
		_, err := runSSHCommand(client, command)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s web restored", target), nil
	})
}

func (s *DefenseService) RestoreDatabaseFromBackup(targetsInput, localPath string) ([]string, error) {
	localPath = resolveBackupPath(localPath)
	return s.runForTargets(targetsInput, func(client *ssh.Client, target string) (string, error) {
		cfg := config.Clone()
		remotePath := fmt.Sprintf("/tmp/%s", filepath.Base(localPath))
		if err := s.uploadFileToRemote(client, localPath, remotePath); err != nil {
			return "", err
		}
		command := fmt.Sprintf("gunzip -c %s | mysql -h %s -P %s -u %s -p%s %s",
			shellQuote(remotePath),
			shellQuote(cfg.Database.Host),
			shellQuote(cfg.Database.Port),
			shellQuote(cfg.Database.Username),
			shellQuote(cfg.Database.Password),
			shellQuote(cfg.Database.Name),
		)
		_, err := runSSHCommand(client, command)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s database restored", target), nil
	})
}

func (s *DefenseService) runForTargets(targetsInput string, fn func(client *ssh.Client, target string) (string, error)) ([]string, error) {
	targets, err := resolveDefenseTargets(targetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found")
	}
	results := make([]string, 0, len(targets))
	for _, target := range targets {
		client, connErr := s.createSSHClient(target)
		if connErr != nil {
			results = append(results, fmt.Sprintf("%s connect failed: %v", target, connErr))
			continue
		}
		result, runErr := fn(client.Client(), target)
		_ = client.Close()
		if runErr != nil {
			results = append(results, fmt.Sprintf("%s failed: %v", target, runErr))
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

func runSSHCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	return string(output), err
}

func runSSHCommandWithInput(client *ssh.Client, command, input string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Start(command); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(input)); err != nil {
		_ = stdin.Close()
		return err
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, stderr.String())
		}
		return err
	}
	return nil
}
