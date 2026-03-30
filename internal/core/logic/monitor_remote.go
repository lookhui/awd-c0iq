package logic

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/util"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/crypto/ssh"
)

var tcpdumpTimestampPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(.+)$`)

func (s *MonitorService) StartRemoteCapture(request RemoteCaptureRequest, progress func(RemoteCaptureEvent)) (*RemoteCaptureState, error) {
	targets, err := resolveRemoteCaptureTargets(request.TargetsInput, s.sshService)
	if err != nil {
		return nil, err
	}
	if err := validateRemoteCaptureSSHConfig(); err != nil {
		return nil, err
	}

	iface := strings.TrimSpace(request.Interface)
	if iface == "" {
		iface = "any"
	}
	filter := strings.TrimSpace(request.Filter)

	s.StopRemoteCapture(nil)

	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()

	s.captureMu.Lock()
	s.captureCtx = ctx
	s.captureCancel = cancel
	s.captureStart = now
	s.captureIface = iface
	s.captureFilter = filter
	s.captureSeq = 0
	s.captureLive = true
	s.captureStop = make(map[string]func(), len(targets))
	s.captureHosts = make(map[string]map[string]struct{}, len(targets))
	s.captureRows = nil
	s.captureHTTP = make(map[string]*liveHTTPStream)
	s.sessions = make(map[string]*RemoteCaptureSession, len(targets))
	for _, target := range targets {
		s.sessions[target] = &RemoteCaptureSession{
			Target:    target,
			Status:    "connecting",
			Message:   "connecting",
			StartedAt: now,
			LastSeen:  now,
		}
	}
	state := s.snapshotCaptureStateLocked()
	s.captureMu.Unlock()

	s.emitCaptureEvent(progress, RemoteCaptureEvent{
		Kind:    "state",
		Message: "remote capture started",
		State:   state,
	})
	logger.Info("remote capture started", "targets", len(targets), "interface", iface, "filter", filter)

	for _, target := range targets {
		go s.captureTargetTraffic(ctx, target, iface, filter, progress)
	}

	return s.GetRemoteCaptureState(), nil
}

func (s *MonitorService) StopRemoteCapture(progress func(RemoteCaptureEvent)) *RemoteCaptureState {
	s.captureMu.Lock()
	cancel := s.captureCancel
	closers := make([]func(), 0, len(s.captureStop))
	for _, closer := range s.captureStop {
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	s.captureCancel = nil
	s.captureCtx = nil
	s.captureLive = false
	for _, session := range s.sessions {
		if session.Status == "running" || session.Status == "connecting" {
			session.Status = "stopping"
			session.Message = "stopping"
			session.LastSeen = time.Now()
		}
	}
	state := s.snapshotCaptureStateLocked()
	s.captureMu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, closer := range closers {
		closer()
	}
	if state != nil {
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "state",
			Message: "remote capture stopped",
			State:   state,
		})
	}
	logger.Info("remote capture stopped")
	return state
}

func (s *MonitorService) GetRemoteCaptureState() *RemoteCaptureState {
	s.captureMu.RLock()
	defer s.captureMu.RUnlock()
	return s.snapshotCaptureStateLocked()
}

func validateRemoteCaptureSSHConfig() error {
	cfg := config.Clone()
	if strings.TrimSpace(cfg.SSH.Username) == "" || strings.TrimSpace(cfg.SSH.Password) == "" {
		return fmt.Errorf("ssh username/password is empty")
	}
	if strings.TrimSpace(cfg.SSH.Port) == "" {
		cfg.SSH.Port = "22"
	}
	return nil
}

func resolveRemoteCaptureTargets(targetsInput string, sshService *ServiceService) ([]string, error) {
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
		return nil, fmt.Errorf("ssh is not connected")
	}
	return util.UniqueSorted(targets), nil
}

func (s *MonitorService) captureTargetTraffic(ctx context.Context, target, iface, filter string, progress func(RemoteCaptureEvent)) {
	startedAt := time.Now()
	client, err := s.createCaptureSSHClient(target)
	if err != nil {
		s.updateCaptureSession(target, "failed", "ssh connect failed", "", err)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: "ssh connect failed",
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
		return
	}
	defer client.Close()

	localIPs := fetchRemoteHostIPs(client.Client(), target)
	s.captureMu.Lock()
	s.captureHosts[target] = localIPs
	s.captureMu.Unlock()

	session, err := client.Client().NewSession()
	if err != nil {
		s.updateCaptureSession(target, "failed", "session create failed", "", err)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: "session create failed",
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		s.updateCaptureSession(target, "failed", "stdout pipe failed", "", err)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: "stdout pipe failed",
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		s.updateCaptureSession(target, "failed", "stderr pipe failed", "", err)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: "stderr pipe failed",
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
		return
	}

	s.registerCaptureStop(target, func() {
		_ = session.Close()
	})

	command := buildRemoteCaptureCommand(iface, target, localIPs, filter)
	if err := session.Start(command); err != nil {
		s.unregisterCaptureStop(target)
		_ = session.Close()
		s.updateCaptureSession(target, "failed", "tcpdump start failed", "", err)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: "tcpdump start failed",
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
		return
	}

	s.updateCaptureSession(target, "running", "tcpdump running", "", nil)
	s.emitCaptureEvent(progress, RemoteCaptureEvent{
		Kind:    "session",
		Message: "tcpdump running",
		Session: s.getCaptureSession(target),
		State:   s.GetRemoteCaptureState(),
	})

	errDone := make(chan error, 1)
	go s.consumeRemoteCaptureOutput(target, stdout, progress)
	go s.consumeRemoteCaptureError(target, stderr, progress)
	go func() {
		errDone <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		waitErr := <-errDone
		_ = waitErr
		s.unregisterCaptureStop(target)
		s.updateCaptureSession(target, "stopped", "capture stopped", "", nil)
	case waitErr := <-errDone:
		s.unregisterCaptureStop(target)
		_ = session.Close()
		if waitErr != nil {
			s.updateCaptureSession(target, "failed", "capture exited", "", waitErr)
		} else {
			s.updateCaptureSession(target, "stopped", "capture completed", "", nil)
		}
	}

	duration := time.Since(startedAt)
	logger.Info("remote capture session finished", "target", target, "duration", duration.String())
	state := s.GetRemoteCaptureState()
	s.emitCaptureEvent(progress, RemoteCaptureEvent{
		Kind:    "session",
		Message: "capture session finished",
		Session: s.getCaptureSession(target),
		State:   state,
	})
}

func (s *MonitorService) createCaptureSSHClient(target string) (sshClientHandle, error) {
	if client, ok := s.sshService.borrowSSHClientForHost(target); ok {
		return sshClientHandle{client: client, shared: true}, nil
	}
	cfg := config.Clone()
	port := strings.TrimSpace(cfg.SSH.Port)
	if port == "" {
		port = "22"
	}
	clientConfig := &ssh.ClientConfig{
		User:            cfg.SSH.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.SSH.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(target, port), clientConfig)
	if err != nil {
		return sshClientHandle{}, err
	}
	return sshClientHandle{client: client}, nil
}

func fetchRemoteHostIPs(client *ssh.Client, fallback string) map[string]struct{} {
	set := map[string]struct{}{}
	output, err := runSSHCommand(client, `hostname -I 2>/dev/null || ip -4 addr show 2>/dev/null | awk '/inet / {print $2}'`)
	if err == nil {
		for _, field := range strings.Fields(strings.ReplaceAll(output, "/", " ")) {
			if net.ParseIP(field) != nil {
				set[field] = struct{}{}
			}
		}
	}
	if fallback != "" {
		set[fallback] = struct{}{}
	}
	return set
}

func buildRemoteCaptureCommand(iface, target string, hosts map[string]struct{}, filter string) string {
	effectiveFilter := buildRemoteCaptureFilter(target, hosts)
	normalizedFilter := normalizeCaptureFilter(filter)
	if normalizedFilter != "" {
		effectiveFilter += " and (" + normalizedFilter + ")"
	}
	linkTypeArg := ""
	if strings.EqualFold(strings.TrimSpace(iface), "any") {
		linkTypeArg = "-y LINUX_SLL"
	}
	base := fmt.Sprintf(`export LC_ALL=C; if ! command -v tcpdump >/dev/null 2>&1; then echo "__AWD_CAPTURE_ERROR__ tcpdump not found" >&2; exit 127; fi; if [ "$(id -u)" = "0" ]; then exec tcpdump -U -nn -s 0 %s -i %s -w - %s; fi; if command -v sudo >/dev/null 2>&1; then exec sudo -n tcpdump -U -nn -s 0 %s -i %s -w - %s; fi; echo "__AWD_CAPTURE_ERROR__ tcpdump requires root privileges" >&2; exit 126`,
		linkTypeArg,
		shellQuote(iface),
		shellQuote(effectiveFilter),
		linkTypeArg,
		shellQuote(iface),
		shellQuote(effectiveFilter),
	)
	return "sh -lc " + shellQuote(base)
}

func buildRemoteCaptureFilter(target string, hosts map[string]struct{}) string {
	candidates := make([]string, 0, len(hosts)+1)
	for host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" {
			candidates = append(candidates, host)
		}
	}
	target = strings.TrimSpace(target)
	if target != "" {
		candidates = append(candidates, target)
	}
	candidates = util.UniqueSorted(candidates)
	if len(candidates) == 0 {
		return "ip or ip6"
	}
	parts := make([]string, 0, len(candidates))
	for _, host := range candidates {
		parts = append(parts, fmt.Sprintf("dst host %s", host))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

func normalizeCaptureFilter(filter string) string {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return ""
	}
	if normalized, ok := normalizeNamedCaptureFilter(filter); ok {
		return normalized
	}
	if normalized, ok := normalizePortShorthandFilter(filter); ok {
		return normalized
	}
	return filter
}

func normalizeNamedCaptureFilter(filter string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(filter))
	switch key {
	case "http":
		return "(port 80 or port 8000 or port 8080 or port 8888)", true
	case "https":
		return "(port 443 or port 8443 or port 9443)", true
	case "http,https", "https,http", "web":
		return "(port 80 or port 443 or port 8000 or port 8080 or port 8443 or port 8888 or port 9443)", true
	default:
		return "", false
	}
}

func normalizePortShorthandFilter(filter string) (string, bool) {
	fields := strings.FieldsFunc(filter, func(r rune) bool {
		switch r {
		case ',', ' ', '\t', '\r', '\n', ';', '|':
			return true
		default:
			return false
		}
	})
	if len(fields) == 0 {
		return "", false
	}

	seen := make(map[int]struct{}, len(fields))
	ports := make([]int, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if !isDigitsOnly(field) {
			return "", false
		}
		port, err := strconv.Atoi(field)
		if err != nil || port <= 0 || port > 65535 {
			return "", false
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	if len(ports) == 1 {
		return fmt.Sprintf("port %d", ports[0]), true
	}

	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("port %d", port))
	}
	return "(" + strings.Join(parts, " or ") + ")", true
}

func (s *MonitorService) consumeRemoteCaptureOutput(target string, reader io.Reader, progress func(RemoteCaptureEvent)) {
	pcapReader, err := pcapgo.NewReader(reader)
	if err != nil {
		s.updateCaptureSession(target, "failed", "pcap reader init failed", "", err)
		return
	}
	packetSource := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	for {
		packet, readErr := packetSource.NextPacket()
		if readErr != nil {
			if readErr != io.EOF {
				s.updateCaptureSession(target, "failed", "capture stream failed", "", readErr)
			}
			return
		}
		record := s.appendCapturePacket(target, packet, s.captureHosts[target])
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "record",
			Message: "remote traffic record",
			Record:  &record,
		})
	}
}

func (s *MonitorService) consumeRemoteCaptureError(target string, reader io.Reader, progress func(RemoteCaptureEvent)) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		status := "warning"
		msg := strings.TrimSpace(strings.TrimPrefix(line, "__AWD_CAPTURE_ERROR__"))
		switch {
		case strings.Contains(lower, "listening on"):
			status = "running"
			msg = "tcpdump listening"
		case strings.Contains(lower, "syntax error in filter expression"):
			status = "failed"
			msg = "tcpdump 过滤器语法错误"
		case strings.Contains(lower, "packets captured"), strings.Contains(lower, "packets received by filter"), strings.Contains(lower, "packets dropped by kernel"):
			status = "stopped"
			msg = line
		case strings.HasPrefix(line, "__AWD_CAPTURE_ERROR__"):
			status = "warning"
		default:
			status = "warning"
		}
		s.updateCaptureSession(target, status, msg, line, nil)
		s.emitCaptureEvent(progress, RemoteCaptureEvent{
			Kind:    "session",
			Message: msg,
			Session: s.getCaptureSession(target),
			State:   s.GetRemoteCaptureState(),
		})
	}
}

func (s *MonitorService) appendCapturePacket(target string, packet gopacket.Packet, hosts map[string]struct{}) RemoteTrafficRecord {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()

	s.captureSeq++
	record := parseRemoteCapturePacket(target, s.captureSeq, packet, hosts)
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}
	s.attachHTTPPreviewLocked(&record, packet)
	s.captureRows = append([]RemoteTrafficRecord{record}, s.captureRows...)
	if len(s.captureRows) > 300 {
		s.captureRows = s.captureRows[:300]
	}
	if session := s.sessions[target]; session != nil {
		session.Status = "running"
		session.Message = "receiving traffic"
		session.LastSeen = time.Now()
		session.LastLine = truncateCaptureLine(record.Summary, 240)
	}
	appendRemoteCaptureHistory(record)
	return record
}

func parseRemoteCapturePacket(target string, seq uint64, packet gopacket.Packet, hosts map[string]struct{}) RemoteTrafficRecord {
	record := RemoteTrafficRecord{
		ID:      fmt.Sprintf("%s-%d", slugCaptureTarget(target), seq),
		Target:  target,
		Raw:     "",
		Summary: "unknown packet",
	}

	metadata := packet.Metadata()
	if metadata != nil {
		record.Timestamp = metadata.Timestamp
	}

	network := packet.NetworkLayer()
	if network == nil {
		record.Direction = "unknown"
		record.Protocol = "unknown"
		record.Summary = truncateCaptureLine(packet.String(), 240)
		record.Raw = record.Summary
		return record
	}
	record.SrcIP = network.NetworkFlow().Src().String()
	record.DstIP = network.NetworkFlow().Dst().String()

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		record.Protocol = "ARP"
		record.Direction = inferCaptureDirection(target, record.SrcIP, record.DstIP, hosts, "")
		record.Summary = "ARP packet"
		record.Raw = record.Summary
		return record
	}

	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		record.SrcPort = fmt.Sprintf("%d", transport.SrcPort)
		record.DstPort = fmt.Sprintf("%d", transport.DstPort)
		record.Direction = inferCaptureDirection(target, record.SrcIP, record.DstIP, hosts, "")
		record.Protocol = inferCaptureProtocol(network.LayerType().String(), record.SrcPort, record.DstPort, "")
		record.Summary = buildTCPSummary(transport)
		payload := sanitizeCapturePayload(transport.Payload)
		if payload != "" {
			record.Raw = payload
		} else {
			record.Raw = record.Summary
		}
	case *layers.UDP:
		record.SrcPort = fmt.Sprintf("%d", transport.SrcPort)
		record.DstPort = fmt.Sprintf("%d", transport.DstPort)
		record.Direction = inferCaptureDirection(target, record.SrcIP, record.DstIP, hosts, "")
		record.Protocol = inferCaptureProtocol(network.LayerType().String(), record.SrcPort, record.DstPort, "udp")
		record.Summary = buildUDPSummary(transport)
		payload := sanitizeCapturePayload(transport.Payload)
		if payload != "" {
			record.Raw = payload
		} else {
			record.Raw = record.Summary
		}
	default:
		record.Timestamp = time.Now()
		record.Direction = "unknown"
		record.Protocol = strings.ToUpper(strings.TrimPrefix(network.LayerType().String(), "LayerType"))
		record.Summary = truncateCaptureLine(packet.String(), 240)
		record.Raw = record.Summary
		return record
	}
	return record
}

func buildTCPSummary(tcp *layers.TCP) string {
	if tcp == nil {
		return "TCP"
	}
	flags := make([]string, 0, 8)
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		flags = append(flags, "DATA")
	}
	return fmt.Sprintf("TCP %s len=%d", strings.Join(flags, ","), len(tcp.Payload))
}

func buildUDPSummary(udp *layers.UDP) string {
	if udp == nil {
		return "UDP"
	}
	return fmt.Sprintf("UDP len=%d", len(udp.Payload))
}

func sanitizeCapturePayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	text := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return r
		case r >= 32 && r <= 126:
			return r
		case r >= 0x4e00 && r <= 0x9fff:
			return r
		default:
			return -1
		}
	}, string(payload))
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\t ")
		if line == "" {
			cleaned = append(cleaned, "")
			continue
		}
		if !looksLikeReadablePayload(line) {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return strings.TrimSpace(strings.Join(cleaned, "\n"))
}

func looksLikeReadablePayload(line string) bool {
	if strings.TrimSpace(line) == "" {
		return true
	}
	printable := 0
	for _, r := range line {
		switch {
		case r == '\t' || r == ' ':
			printable++
		case r >= 32 && r <= 126:
			printable++
		case r >= 0x4e00 && r <= 0x9fff:
			printable++
		}
	}
	return printable*100 >= len([]rune(line))*65
}

func splitTCPDumpLine(line string) (timestamp, direction, protocol, srcEndpoint, dstEndpoint, summary string, ok bool) {
	matches := tcpdumpTimestampPattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 3 {
		return "", "", "", "", "", "", false
	}

	timestamp = matches[1]
	rest := matches[2]
	if strings.Contains(rest, " In  ") {
		direction = "incoming"
	} else if strings.Contains(rest, " Out ") || strings.Contains(rest, " Out  ") {
		direction = "outgoing"
	}

	for _, marker := range []string{" IP6 ", " IP ", " ARP "} {
		index := strings.Index(rest, marker)
		if index < 0 {
			continue
		}
		protocol = strings.TrimSpace(marker)
		payload := strings.TrimSpace(rest[index+len(marker):])
		parts := strings.SplitN(payload, " > ", 2)
		if len(parts) != 2 {
			return "", "", "", "", "", "", false
		}
		srcEndpoint = strings.TrimSpace(parts[0])
		right := parts[1]
		colon := strings.Index(right, ":")
		if colon < 0 {
			return "", "", "", "", "", "", false
		}
		dstEndpoint = strings.TrimSpace(right[:colon])
		summary = strings.TrimSpace(right[colon+1:])
		return timestamp, direction, protocol, srcEndpoint, dstEndpoint, summary, true
	}
	return "", "", "", "", "", "", false
}

func splitCaptureEndpoint(endpoint string) (string, string) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", ""
	}
	lastDot := strings.LastIndex(endpoint, ".")
	if lastDot <= 0 || lastDot == len(endpoint)-1 {
		return endpoint, ""
	}
	port := endpoint[lastDot+1:]
	if !isDigitsOnly(port) {
		return endpoint, ""
	}
	return endpoint[:lastDot], port
}

func inferCaptureProtocol(baseProtocol, srcPort, dstPort, summary string) string {
	baseProtocol = strings.ToUpper(strings.TrimSpace(baseProtocol))
	summaryLower := strings.ToLower(strings.TrimSpace(summary))

	if application := inferApplicationProtocol(srcPort, dstPort, summaryLower); application != "" {
		return application
	}

	switch {
	case baseProtocol == "ARP":
		return "ARP"
	case baseProtocol == "IPV6":
		return "IPv6"
	case baseProtocol == "IPV4":
		return "IP"
	case strings.Contains(summaryLower, "icmp6"):
		return "ICMPv6"
	case strings.Contains(summaryLower, "icmp"):
		return "ICMP"
	case strings.HasPrefix(summaryLower, "udp"):
		return "UDP"
	case strings.Contains(summary, "Flags ["), srcPort != "", dstPort != "":
		return "TCP"
	case baseProtocol == "IP":
		return "IP"
	default:
		return baseProtocol
	}
}

func inferApplicationProtocol(srcPort, dstPort, summaryLower string) string {
	if strings.Contains(summaryLower, "http/") || strings.Contains(summaryLower, "get /") || strings.Contains(summaryLower, "post /") {
		return "HTTP"
	}

	for _, port := range []string{srcPort, dstPort} {
		switch port {
		case "80", "8000", "8080", "8888":
			return "HTTP"
		case "443", "8443", "9443":
			return "HTTPS"
		case "22":
			return "SSH"
		case "53":
			return "DNS"
		case "3306":
			return "MySQL"
		case "6379":
			return "Redis"
		case "27017":
			return "MongoDB"
		}
	}
	return ""
}

func (s *MonitorService) attachHTTPPreviewLocked(record *RemoteTrafficRecord, packet gopacket.Packet) {
	if record == nil || record.Protocol == "HTTPS" {
		if record != nil && record.Protocol == "HTTPS" && strings.TrimSpace(record.Raw) == "" {
			record.Raw = "HTTPS/TLS 流量无法直接看到明文请求头和请求体。"
		}
		return
	}
	transport, ok := packet.TransportLayer().(*layers.TCP)
	if !ok || len(transport.Payload) == 0 {
		return
	}

	payload := sanitizeCapturePayload(transport.Payload)
	if payload == "" {
		return
	}

	streamKey := fmt.Sprintf("%s:%s>%s:%s", record.SrcIP, record.SrcPort, record.DstIP, record.DstPort)
	now := record.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	if summary, method, path, status, body, ok := extractHTTPMessage(payload); ok {
		stream := &liveHTTPStream{
			Summary:  summary,
			Body:     body,
			Method:   method,
			Path:     path,
			Status:   status,
			LastSeen: now,
		}
		if s.captureHTTP == nil {
			s.captureHTTP = make(map[string]*liveHTTPStream)
		}
		s.captureHTTP[streamKey] = stream
		record.Protocol = "HTTP"
		record.Summary = summary
		record.Method = method
		record.Path = path
		record.Status = status
		record.Raw = body
		return
	}

	stream := s.captureHTTP[streamKey]
	if stream == nil || now.Sub(stream.LastSeen) > 15*time.Second {
		return
	}
	if continuation := strings.TrimSpace(payload); continuation != "" {
		if stream.Body != "" {
			stream.Body += "\n"
		}
		stream.Body += continuation
		if len(stream.Body) > 64*1024 {
			stream.Body = stream.Body[len(stream.Body)-64*1024:]
		}
	}
	stream.LastSeen = now
	record.Protocol = "HTTP"
	record.Summary = stream.Summary
	record.Method = stream.Method
	record.Path = stream.Path
	record.Status = stream.Status
	record.Raw = stream.Body
}

var httpRequestPattern = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d$`)
var httpResponsePattern = regexp.MustCompile(`^HTTP/\d\.\d\s+(\d{3})`)

func extractHTTPMessage(payload string) (summary, method, path, status, body string, ok bool) {
	payload = strings.ReplaceAll(payload, "\r\n", "\n")
	payload = strings.ReplaceAll(payload, "\r", "\n")
	lines := strings.Split(payload, "\n")
	for index, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if matches := httpRequestPattern.FindStringSubmatch(line); len(matches) == 3 {
			method = matches[1]
			path = matches[2]
			summary = method + " " + path
			body = strings.TrimSpace(strings.Join(lines[index:], "\n"))
			return summary, method, path, "", body, true
		}
		if matches := httpResponsePattern.FindStringSubmatch(line); len(matches) == 2 {
			status = matches[1]
			summary = "HTTP " + status
			body = strings.TrimSpace(strings.Join(lines[index:], "\n"))
			return summary, "", "", status, body, true
		}
	}
	return "", "", "", "", "", false
}

func inferCaptureDirection(target, srcIP, dstIP string, hosts map[string]struct{}, hinted string) string {
	if hinted != "" {
		return hinted
	}
	if _, ok := hosts[dstIP]; ok {
		return "incoming"
	}
	if _, ok := hosts[srcIP]; ok {
		return "outgoing"
	}
	switch {
	case dstIP == target:
		return "incoming"
	case srcIP == target:
		return "outgoing"
	default:
		return "unknown"
	}
}

func isDigitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func truncateCaptureLine(line string, max int) string {
	if len(line) <= max {
		return line
	}
	return line[:max-3] + "..."
}

func slugCaptureTarget(target string) string {
	replacer := strings.NewReplacer(".", "-", ":", "-", "/", "-", "\\", "-")
	value := replacer.Replace(strings.TrimSpace(target))
	value = strings.Trim(value, "-")
	if value == "" {
		return "capture"
	}
	return value
}

func (s *MonitorService) updateCaptureSession(target, status, message, line string, err error) {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()

	session := s.sessions[target]
	if session == nil {
		session = &RemoteCaptureSession{Target: target, StartedAt: time.Now()}
		s.sessions[target] = session
	}
	session.Status = status
	if strings.TrimSpace(message) != "" {
		session.Message = message
	}
	if strings.TrimSpace(line) != "" {
		session.LastLine = truncateCaptureLine(line, 240)
	}
	session.LastSeen = time.Now()
	if err != nil {
		session.Error = err.Error()
	}
	s.refreshCaptureLiveLocked()
}

func (s *MonitorService) getCaptureSession(target string) *RemoteCaptureSession {
	s.captureMu.RLock()
	defer s.captureMu.RUnlock()
	session := s.sessions[target]
	if session == nil {
		return nil
	}
	copyValue := *session
	return &copyValue
}

func (s *MonitorService) registerCaptureStop(target string, closer func()) {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	if s.captureStop == nil {
		s.captureStop = map[string]func(){}
	}
	s.captureStop[target] = closer
}

func (s *MonitorService) unregisterCaptureStop(target string) {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	delete(s.captureStop, target)
	s.refreshCaptureLiveLocked()
}

func (s *MonitorService) refreshCaptureLiveLocked() {
	s.captureLive = false
	for _, session := range s.sessions {
		if session.Status == "running" || session.Status == "connecting" {
			s.captureLive = true
			return
		}
	}
}

func (s *MonitorService) snapshotCaptureStateLocked() *RemoteCaptureState {
	state := &RemoteCaptureState{
		Running:   s.captureLive,
		Interface: s.captureIface,
		Filter:    s.captureFilter,
		StartedAt: s.captureStart,
	}
	if len(s.captureRows) > 0 {
		state.Records = append([]RemoteTrafficRecord(nil), s.captureRows...)
	}
	if len(s.sessions) == 0 {
		return state
	}
	targets := make([]string, 0, len(s.sessions))
	for target := range s.sessions {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	state.Sessions = make([]RemoteCaptureSession, 0, len(targets))
	for _, target := range targets {
		if session := s.sessions[target]; session != nil {
			state.Sessions = append(state.Sessions, *session)
		}
	}
	return state
}

func (s *MonitorService) emitCaptureEvent(progress func(RemoteCaptureEvent), event RemoteCaptureEvent) {
	if progress != nil {
		progress(event)
	}
}

func captureHistoryPath() string {
	return filepath.Join(util.OutputDir(), "traffic_capture.jsonl")
}

func appendRemoteCaptureHistory(record RemoteTrafficRecord) {
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	_ = util.AppendText(captureHistoryPath(), string(data))
}

func GetCaptureHistory(query string, limit int) ([]RemoteTrafficRecord, error) {
	data, err := os.ReadFile(captureHistoryPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	terms := parseCaptureHistoryTerms(query)
	rows := make([]RemoteTrafficRecord, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var record RemoteTrafficRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if !captureHistoryMatchesQuery(record, terms) {
			continue
		}
		rows = append(rows, record)
		if limit > 0 && len(rows) >= limit {
			break
		}
	}
	return rows, nil
}

func parseCaptureHistoryTerms(query string) []string {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return nil
	}
	rawTerms := strings.Split(query, "&")
	terms := make([]string, 0, len(rawTerms))
	for _, term := range rawTerms {
		term = strings.TrimSpace(term)
		if term != "" {
			terms = append(terms, term)
		}
	}
	return util.UniqueSorted(terms)
}

func captureHistoryMatchesQuery(record RemoteTrafficRecord, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		record.Target,
		record.Direction,
		record.Protocol,
		record.Method,
		record.Path,
		record.Status,
		record.SrcIP,
		record.SrcPort,
		record.DstIP,
		record.DstPort,
		record.Summary,
		record.Raw,
	}, " "))
	for _, term := range terms {
		if !strings.Contains(haystack, term) {
			return false
		}
	}
	return true
}
