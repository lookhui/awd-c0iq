package logic

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

func NewDetectionService() *DetectionService {
	return &DetectionService{
		AliveHosts: make([]string, 0),
		ExistHosts: make(map[string]struct{}),
	}
}

func (s *DetectionService) CheckLive(host string) bool {
	if host == "" {
		return false
	}
	if s.probeWithICMP(host) {
		s.handleAliveHosts(host)
		return true
	}
	for _, port := range []string{"80", "22", "443"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
		if err == nil {
			_ = conn.Close()
			s.handleAliveHosts(host)
			return true
		}
	}
	return false
}

func (s *DetectionService) handleAliveHosts(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.ExistHosts[host]; exists {
		return
	}
	s.ExistHosts[host] = struct{}{}
	s.AliveHosts = append(s.AliveHosts, host)
}

func (s *DetectionService) probeWithICMP(host string) bool {
	return RunPing(host)
}

func RunIcmp1(host string) bool  { return RunPing(host) }
func RunIcmp2(host string) bool  { return RunPing(host) }
func icmpAlive(host string) bool { return RunPing(host) }

func RunPing(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := []string{}
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", "1000", host}
	} else {
		args = []string{"-c", "1", "-W", "1", host}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	return cmd.Run() == nil
}

func execCommandPing(host string) bool { return RunPing(host) }
func makemsg(host string) string       { return fmt.Sprintf("checking %s", host) }

func GetSubnetStats(hosts []string) map[string]int {
	stats := make(map[string]int)
	for _, host := range hosts {
		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			continue
		}
		key := strings.Join(parts[:3], ".") + ".0/24"
		stats[key]++
	}
	return stats
}

func DetectHosts(targets []string, concurrency int) []string {
	service := NewDetectionService()
	if concurrency <= 0 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			service.CheckLive(target)
		}()
	}
	wg.Wait()
	return service.AliveHosts
}
