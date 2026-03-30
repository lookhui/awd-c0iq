package pcapsearch

import (
	"fmt"
	"sync"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
)

type SearchDocument struct {
	ID          string    `json:"id"`
	PcapID      uint      `json:"pcapId"`
	ClientID    string    `json:"clientId"`
	Content     string    `json:"content"`
	SrcIP       string    `json:"srcIp"`
	DstIP       string    `json:"dstIp"`
	SrcPort     string    `json:"srcPort"`
	DstPort     string    `json:"dstPort"`
	StartTime   int64     `json:"startTime"`
	DurationSec int64     `json:"durationSec"`
	NumPackets  int64     `json:"numPackets"`
	SizeBytes   int64     `json:"sizeBytes"`
	CreatedAt   time.Time `json:"createdAt"`
}

type SearchResult struct {
	ID          string    `json:"id"`
	PcapID      uint      `json:"pcapId"`
	ClientID    string    `json:"clientId"`
	Content     string    `json:"content"`
	SrcIP       string    `json:"srcIp"`
	DstIP       string    `json:"dstIp"`
	SrcPort     string    `json:"srcPort"`
	DstPort     string    `json:"dstPort"`
	StartTime   int64     `json:"startTime"`
	DurationSec int64     `json:"durationSec"`
	NumPackets  int64     `json:"numPackets"`
	SizeBytes   int64     `json:"sizeBytes"`
	CreatedAt   time.Time `json:"createdAt"`
	Score       float64   `json:"score"`
}

type Service struct {
	index bleve.Index
	mu    sync.RWMutex
}

var global = &Service{}

func Init(indexPath string) error {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.index != nil {
		return nil
	}
	if index, err := bleve.Open(indexPath); err == nil {
		global.index = index
		return nil
	}
	index, err := bleve.New(indexPath, createMapping())
	if err != nil {
		return err
	}
	global.index = index
	return nil
}

func bleveConfig() *Service {
	return global
}

func createMapping() mapping.IndexMapping {
	indexMapping := bleve.NewIndexMapping()
	docMapping := bleve.NewDocumentMapping()

	textField := bleve.NewTextFieldMapping()
	textField.Store = true

	keywordField := bleve.NewKeywordFieldMapping()
	keywordField.Store = true

	numberField := bleve.NewNumericFieldMapping()
	numberField.Store = true

	dateField := bleve.NewDateTimeFieldMapping()
	dateField.Store = true

	docMapping.AddFieldMappingsAt("id", keywordField)
	docMapping.AddFieldMappingsAt("pcap_id", numberField)
	docMapping.AddFieldMappingsAt("client_id", keywordField)
	docMapping.AddFieldMappingsAt("content", textField)
	docMapping.AddFieldMappingsAt("src_ip", keywordField)
	docMapping.AddFieldMappingsAt("dst_ip", keywordField)
	docMapping.AddFieldMappingsAt("src_port", keywordField)
	docMapping.AddFieldMappingsAt("dst_port", keywordField)
	docMapping.AddFieldMappingsAt("start_time", numberField)
	docMapping.AddFieldMappingsAt("duration_sec", numberField)
	docMapping.AddFieldMappingsAt("num_packets", numberField)
	docMapping.AddFieldMappingsAt("size_bytes", numberField)
	docMapping.AddFieldMappingsAt("created_at", dateField)

	indexMapping.DefaultMapping = docMapping
	return indexMapping
}

func IndexDocument(doc SearchDocument) error {
	global.mu.RLock()
	defer global.mu.RUnlock()
	if global.index == nil {
		return fmt.Errorf("bleve index not initialized")
	}
	return global.index.Index(doc.ID, map[string]any{
		"id":           doc.ID,
		"pcap_id":      doc.PcapID,
		"client_id":    doc.ClientID,
		"content":      doc.Content,
		"src_ip":       doc.SrcIP,
		"dst_ip":       doc.DstIP,
		"src_port":     doc.SrcPort,
		"dst_port":     doc.DstPort,
		"start_time":   doc.StartTime,
		"duration_sec": doc.DurationSec,
		"num_packets":  doc.NumPackets,
		"size_bytes":   doc.SizeBytes,
		"created_at":   doc.CreatedAt,
	})
}

func Search(query string, page, size int) ([]SearchResult, error) {
	global.mu.RLock()
	defer global.mu.RUnlock()
	if global.index == nil {
		return nil, fmt.Errorf("bleve index not initialized")
	}
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	request := bleve.NewSearchRequestOptions(bleve.NewQueryStringQuery(query), size, (page-1)*size, false)
	request.Fields = []string{
		"id", "pcap_id", "client_id", "content", "src_ip", "dst_ip", "src_port", "dst_port",
		"start_time", "duration_sec", "num_packets", "size_bytes", "created_at",
	}
	result, err := global.index.Search(request)
	if err != nil {
		return nil, err
	}
	items := make([]SearchResult, 0, len(result.Hits))
	for _, hit := range result.Hits {
		items = append(items, SearchResult{
			ID:          hit.ID,
			PcapID:      uint(fieldFloat(hit.Fields["pcap_id"])),
			ClientID:    fieldString(hit.Fields["client_id"]),
			Content:     fieldString(hit.Fields["content"]),
			SrcIP:       fieldString(hit.Fields["src_ip"]),
			DstIP:       fieldString(hit.Fields["dst_ip"]),
			SrcPort:     fieldString(hit.Fields["src_port"]),
			DstPort:     fieldString(hit.Fields["dst_port"]),
			StartTime:   int64(fieldFloat(hit.Fields["start_time"])),
			DurationSec: int64(fieldFloat(hit.Fields["duration_sec"])),
			NumPackets:  int64(fieldFloat(hit.Fields["num_packets"])),
			SizeBytes:   int64(fieldFloat(hit.Fields["size_bytes"])),
			Score:       hit.Score,
		})
	}
	return items, nil
}

func fieldString(value any) string {
	if value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprint(value)
}

func fieldFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0
	}
}
