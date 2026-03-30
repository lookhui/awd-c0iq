package logic

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNormalizeCaptureFilter_PortShorthand(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "single_port", input: "80", expect: "port 80"},
		{name: "comma_ports", input: "80,443", expect: "(port 80 or port 443)"},
		{name: "space_ports", input: "80 443 22", expect: "(port 22 or port 80 or port 443)"},
		{name: "raw_bpf", input: "tcp and port 80", expect: "tcp and port 80"},
		{name: "http_keyword", input: "http", expect: "(port 80 or port 8000 or port 8080 or port 8888)"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeCaptureFilter(tc.input)
			if got != tc.expect {
				t.Fatalf("normalizeCaptureFilter(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestBuildRemoteCaptureCommand_AnyUsesLinuxSLL(t *testing.T) {
	t.Parallel()

	command := buildRemoteCaptureCommand("any", "10.0.0.1", map[string]struct{}{"10.0.0.1": {}}, "")
	if !strings.Contains(command, "-y LINUX_SLL") {
		t.Fatalf("expected tcpdump command to force LINUX_SLL for any interface, got %q", command)
	}
}

func TestNormalizeCaptureFilter_InvalidPortStaysRaw(t *testing.T) {
	t.Parallel()

	input := "70000"
	if got := normalizeCaptureFilter(input); got != input {
		t.Fatalf("normalizeCaptureFilter(%q) = %q, want raw value preserved", input, got)
	}
}

func TestInferCaptureProtocol(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		baseProtocol string
		srcPort      string
		dstPort      string
		summary      string
		expect       string
	}{
		{name: "http_by_port", baseProtocol: "IP", srcPort: "51920", dstPort: "80", summary: "Flags [P.], seq 1:156, ack 1, win 502, length 155", expect: "HTTP"},
		{name: "https_by_port", baseProtocol: "IP", srcPort: "443", dstPort: "51920", summary: "Flags [.], ack 1, win 502, length 0", expect: "HTTPS"},
		{name: "ssh_by_port", baseProtocol: "IP", srcPort: "22", dstPort: "51920", summary: "Flags [P.], length 64", expect: "SSH"},
		{name: "udp_fallback", baseProtocol: "IP", srcPort: "5353", dstPort: "5353", summary: "UDP, length 32", expect: "UDP"},
		{name: "arp_passthrough", baseProtocol: "ARP", summary: "Request who-has 1.1.1.1 tell 1.1.1.2", expect: "ARP"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := inferCaptureProtocol(tc.baseProtocol, tc.srcPort, tc.dstPort, tc.summary)
			if got != tc.expect {
				t.Fatalf("inferCaptureProtocol(...) = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestExtractHTTPMessage(t *testing.T) {
	t.Parallel()

	payload := "POST /login HTTP/1.1\r\nHost: example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=123456"
	summary, method, path, status, body, ok := extractHTTPMessage(payload)
	if !ok {
		t.Fatalf("extractHTTPMessage() expected ok=true")
	}
	if summary != "POST /login" || method != "POST" || path != "/login" || status != "" {
		t.Fatalf("unexpected parsed metadata: summary=%q method=%q path=%q status=%q", summary, method, path, status)
	}
	if body == "" || body[:5] != "POST " {
		t.Fatalf("expected full http body, got %q", body)
	}
}

func TestAttachHTTPPreviewLocked_POSTBody(t *testing.T) {
	t.Parallel()

	payload := []byte("POST /login HTTP/1.1\r\nHost: example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=123456")
	packet := mustBuildTestPacket(t, "10.10.10.2", "10.10.10.3", 52340, 80, payload)

	service := NewMonitorService(nil)
	record := parseRemoteCapturePacket("10.10.10.3", 1, packet, map[string]struct{}{
		"10.10.10.3": {},
	})

	service.captureMu.Lock()
	service.attachHTTPPreviewLocked(&record, packet)
	service.captureMu.Unlock()

	if record.Protocol != "HTTP" {
		t.Fatalf("expected protocol HTTP, got %q", record.Protocol)
	}
	if record.Method != "POST" || record.Path != "/login" {
		t.Fatalf("unexpected http metadata: method=%q path=%q", record.Method, record.Path)
	}
	if record.Summary != "POST /login" {
		t.Fatalf("unexpected summary: %q", record.Summary)
	}
	if record.Raw == "" || !containsAll(record.Raw, []string{"POST /login HTTP/1.1", "user=admin&pass=123456"}) {
		t.Fatalf("expected raw http payload with request body, got %q", record.Raw)
	}
}

func TestCaptureHistoryMatchesQuery_WithAndTerms(t *testing.T) {
	t.Parallel()

	record := RemoteTrafficRecord{
		Protocol: "HTTP",
		Method:   "POST",
		SrcIP:    "172.27.132.236",
		DstPort:  "80",
		Raw:      "POST /login HTTP/1.1\nuser=admin&pass=123456",
	}

	if !captureHistoryMatchesQuery(record, parseCaptureHistoryTerms("80&post&172.27.132.236")) {
		t.Fatalf("expected AND query to match record")
	}
	if captureHistoryMatchesQuery(record, parseCaptureHistoryTerms("80&get")) {
		t.Fatalf("expected unmatched AND query to fail")
	}
}

func mustBuildTestPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort int, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     100,
		ACK:     true,
		PSH:     true,
		Window:  14600,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum failed: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return packet
}

func containsAll(value string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
