package logic

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"awd-h1m-pro/internal/util"

	"golang.org/x/crypto/ssh"
)

func (s *ServiceService) ChangeSSHPasswords(params SSHPasswordChangeParams) (*SSHPasswordChangeResponse, error) {
	targets := ParseTargetsInput(params.TargetsInput)
	if len(targets) == 0 {
		if host := s.currentSSHHost(); host != "" {
			targets = []string{host}
		}
	}
	if len(targets) == 0 {
		loaded, err := LoadTargetsFromOutput()
		if err == nil {
			targets = loaded
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}
	if params.Port == "" {
		params.Port = "22"
	}
	if params.MaxConcurrency <= 0 {
		params.MaxConcurrency = 10
	}
	resp := &SSHPasswordChangeResponse{
		Results: make([]SSHPasswordChangeResult, 0, len(targets)),
		Total:   int64(len(targets)),
	}
	sem := make(chan struct{}, params.MaxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successHosts := make([]string, 0)
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := processHost(target, params.Username, params.Port, params.OldPasswords, params.NewPassword)
			mu.Lock()
			resp.Results = append(resp.Results, result)
			switch result.Status {
			case "success":
				resp.Success++
				successHosts = append(successHosts, target)
			case "timeout":
				resp.Timeout++
			case "auth_failed":
				resp.AuthFailed++
			default:
				resp.Error++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	_ = util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "ssh_password_success.txt"), successHosts)
	return resp, nil
}

func processHost(ip, username, port string, oldPasswords []string, newPassword string) SSHPasswordChangeResult {
	for _, oldPassword := range oldPasswords {
		client, err := dialSSH(ip, port, username, oldPassword)
		if err != nil {
			status := classifyDialError(err)
			if status == "auth_failed" {
				continue
			}
			return SSHPasswordChangeResult{IP: ip, UsedPassword: oldPassword, Status: status, Message: err.Error()}
		}
		defer client.Close()
		if err := changePassword(client, username, newPassword); err != nil {
			return SSHPasswordChangeResult{IP: ip, UsedPassword: oldPassword, Status: "error", Message: err.Error()}
		}
		return SSHPasswordChangeResult{IP: ip, UsedPassword: oldPassword, Status: "success", Message: "password changed"}
	}
	return SSHPasswordChangeResult{IP: ip, Status: "auth_failed", Message: "all passwords failed"}
}

func dialSSH(ip, port, username, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", net.JoinHostPort(ip, port), config)
}

func changePassword(client *ssh.Client, username, newPassword string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	command := fmt.Sprintf("echo %s:%s | chpasswd", shellQuote(username), shellQuote(newPassword))
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func classifyDialError(err error) string {
	if err == nil {
		return "success"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "permission denied"):
		return "auth_failed"
	default:
		return "error"
	}
}
