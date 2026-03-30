package logic

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

type sshClientHandle struct {
	client *ssh.Client
	shared bool
}

func (h sshClientHandle) Client() *ssh.Client {
	return h.client
}

func (h sshClientHandle) Close() error {
	if h.shared || h.client == nil {
		return nil
	}
	return h.client.Close()
}

func (s *ServiceService) currentSSHHost() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sshClient == nil {
		return ""
	}
	return strings.TrimSpace(s.sshRequest.Host)
}

func (s *ServiceService) borrowSSHClientForHost(host string) (*ssh.Client, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sshClient == nil {
		return nil, false
	}
	currentHost := strings.TrimSpace(s.sshRequest.Host)
	requestedHost := strings.TrimSpace(host)
	if requestedHost != "" && !strings.EqualFold(requestedHost, currentHost) {
		return nil, false
	}
	return s.sshClient, true
}

func resolveActiveSSHHost(sshService *ServiceService) string {
	if sshService == nil {
		return ""
	}
	return sshService.currentSSHHost()
}
