package pcapstore

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/pcapsearch"

	"github.com/glebarez/sqlite"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gorm.io/gorm"
)

type PcapFile struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Filename  string    `json:"filename"`
	ClientID  string    `json:"clientId"`
	FileSize  int64     `json:"fileSize"`
	MD5       string    `json:"md5"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type PcapRecord struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	PcapFileID  uint      `json:"pcapFileId"`
	ClientID    string    `json:"clientId"`
	SrcIP       string    `json:"srcIp"`
	DstIP       string    `json:"dstIp"`
	SrcPort     string    `json:"srcPort"`
	DstPort     string    `json:"dstPort"`
	StartTime   int64     `json:"startTime"`
	DurationSec int64     `json:"durationSec"`
	NumPackets  int64     `json:"numPackets"`
	SizeBytes   int64     `json:"sizeBytes"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type PcapDetail struct {
	PcapID        uint   `json:"pcapId"`
	ClientID      string `json:"clientId"`
	SrcIP         string `json:"srcIp"`
	DstIP         string `json:"dstIp"`
	SrcPort       string `json:"srcPort"`
	DstPort       string `json:"dstPort"`
	StartTime     int64  `json:"startTime"`
	DurationSec   int64  `json:"durationSec"`
	NumPackets    int64  `json:"numPackets"`
	SizeBytes     int64  `json:"sizeBytes"`
	ClientContent string `json:"clientContent"`
	ServerContent string `json:"serverContent"`
}

type queuedFile struct {
	Path     string
	ClientID string
}

type aggregatedStream struct {
	ClientID    string
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	StartTime   time.Time
	EndTime     time.Time
	NumPackets  int64
	SizeBytes   int64
	ClientParts []string
	ServerParts []string
}

var (
	db        *gorm.DB
	queue     chan queuedFile
	startOnce sync.Once
)

func Init(path string) error {
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return err
	}
	if err := database.AutoMigrate(&PcapFile{}, &PcapRecord{}); err != nil {
		return err
	}
	db = database
	return nil
}

func StartProcessor() {
	startOnce.Do(func() {
		queue = make(chan queuedFile, 128)
		workerCount := 6
		logger.Info("starting pcap processor", "workers", workerCount)
		for i := 0; i < workerCount; i++ {
			go workerLoop()
		}
	})
}

func EnqueueFile(path, clientID string) {
	if queue == nil {
		StartProcessor()
	}
	queue <- queuedFile{Path: path, ClientID: clientID}
}

func workerLoop() {
	for item := range queue {
		if err := handleFile(item); err != nil {
			logger.Error("failed to handle pcap file", "path", item.Path, "error", err.Error())
		}
	}
}

func handleFile(item queuedFile) error {
	if db == nil {
		return fmt.Errorf("pcap database not initialized")
	}
	md5Value, err := calcFileMD5(item.Path)
	if err != nil {
		return err
	}
	info, err := os.Stat(item.Path)
	if err != nil {
		return err
	}
	pcapFile := PcapFile{
		Filename:  info.Name(),
		ClientID:  item.ClientID,
		FileSize:  info.Size(),
		MD5:       md5Value,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Create(&pcapFile).Error; err != nil {
		return err
	}
	records, err := parsePcapFile(item.Path, item.ClientID)
	if err != nil {
		return err
	}
	for _, record := range records {
		record.PcapFileID = pcapFile.ID
		record.CreatedAt = time.Now()
		record.UpdatedAt = time.Now()
		if err := db.Create(&record).Error; err != nil {
			return err
		}
		_ = pcapsearch.IndexDocument(pcapsearch.SearchDocument{
			ID:          fmt.Sprintf("%d", record.ID),
			PcapID:      record.ID,
			ClientID:    record.ClientID,
			Content:     record.Content,
			SrcIP:       record.SrcIP,
			DstIP:       record.DstIP,
			SrcPort:     record.SrcPort,
			DstPort:     record.DstPort,
			StartTime:   record.StartTime,
			DurationSec: record.DurationSec,
			NumPackets:  record.NumPackets,
			SizeBytes:   record.SizeBytes,
			CreatedAt:   record.CreatedAt,
		})
	}
	return nil
}

func calcFileMD5(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func parsePcapFile(path, clientID string) ([]PcapRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	streams := map[string]*aggregatedStream{}
	for packet := range packetSource.Packets() {
		network := packet.NetworkLayer()
		transport := packet.TransportLayer()
		if network == nil || transport == nil {
			continue
		}
		tcp, ok := transport.(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			continue
		}
		srcIP, dstIP := network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
		srcPort, dstPort := fmt.Sprintf("%d", tcp.SrcPort), fmt.Sprintf("%d", tcp.DstPort)
		key, reverse := canonicalStreamKey(srcIP, dstIP, srcPort, dstPort)
		stream, ok := streams[key]
		if !ok {
			stream = &aggregatedStream{
				ClientID:  clientID,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				StartTime: packet.Metadata().Timestamp,
				EndTime:   packet.Metadata().Timestamp,
			}
			streams[key] = stream
		}
		if packet.Metadata().Timestamp.Before(stream.StartTime) {
			stream.StartTime = packet.Metadata().Timestamp
		}
		if packet.Metadata().Timestamp.After(stream.EndTime) {
			stream.EndTime = packet.Metadata().Timestamp
		}
		stream.NumPackets++
		stream.SizeBytes += int64(len(tcp.Payload))
		text := parseHTTPStream(decodePayloadToText(tcp.Payload))
		if text == "" {
			continue
		}
		if reverse {
			stream.ServerParts = append(stream.ServerParts, text)
		} else {
			stream.ClientParts = append(stream.ClientParts, text)
		}
	}
	records := make([]PcapRecord, 0, len(streams))
	for _, stream := range streams {
		content := strings.TrimSpace("CLIENT:\n" + strings.Join(stream.ClientParts, "\n") + "\n\nSERVER:\n" + strings.Join(stream.ServerParts, "\n"))
		records = append(records, PcapRecord{
			ClientID:    stream.ClientID,
			SrcIP:       stream.SrcIP,
			DstIP:       stream.DstIP,
			SrcPort:     stream.SrcPort,
			DstPort:     stream.DstPort,
			StartTime:   stream.StartTime.Unix(),
			DurationSec: int64(stream.EndTime.Sub(stream.StartTime).Seconds()),
			NumPackets:  stream.NumPackets,
			SizeBytes:   stream.SizeBytes,
			Content:     content,
		})
	}
	return records, nil
}

func sanitizePayload(value string) string {
	value = strings.Map(func(r rune) rune {
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
	}, value)
	return strings.TrimSpace(value)
}

func decodePayloadToText(payload []byte) string {
	return sanitizePayload(string(payload))
}

func parseHTTPStream(payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return ""
	}
	lines := strings.Split(payload, "\n")
	if len(lines) > 64 {
		lines = lines[:64]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func GetPcapDetail(id uint) (*PcapDetail, error) {
	if db == nil {
		return nil, fmt.Errorf("pcap database not initialized")
	}
	var record PcapRecord
	if err := db.First(&record, id).Error; err != nil {
		return nil, err
	}
	return buildPcapDetail(record), nil
}

func buildPcapDetail(record PcapRecord) *PcapDetail {
	clientContent := record.Content
	serverContent := ""
	if parts := strings.Split(record.Content, "\n\nSERVER:\n"); len(parts) == 2 {
		clientContent = strings.TrimPrefix(parts[0], "CLIENT:\n")
		serverContent = parts[1]
	}
	return &PcapDetail{
		PcapID:        record.ID,
		ClientID:      record.ClientID,
		SrcIP:         record.SrcIP,
		DstIP:         record.DstIP,
		SrcPort:       record.SrcPort,
		DstPort:       record.DstPort,
		StartTime:     record.StartTime,
		DurationSec:   record.DurationSec,
		NumPackets:    record.NumPackets,
		SizeBytes:     record.SizeBytes,
		ClientContent: strings.TrimSpace(clientContent),
		ServerContent: strings.TrimSpace(serverContent),
	}
}

func canonicalStreamKey(srcIP, dstIP, srcPort, dstPort string) (string, bool) {
	left := fmt.Sprintf("%s:%s", srcIP, srcPort)
	right := fmt.Sprintf("%s:%s", dstIP, dstPort)
	if left <= right {
		return left + "|" + right, false
	}
	return right + "|" + left, true
}
