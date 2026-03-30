package pcapserver

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/pcapstore"
)

type uploadResponse struct {
	Message  string `json:"message"`
	Filename string `json:"filename,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Error    string `json:"error,omitempty"`
}

var (
	serverOnce sync.Once
	serverInst *http.Server
	uploadDir  string
)

func Start(addr, dir string) error {
	var startErr error
	serverOnce.Do(func() {
		uploadDir = dir
		if err := os.MkdirAll(dir, 0o755); err != nil {
			startErr = err
			return
		}
		mux := http.NewServeMux()
		for _, route := range []string{"/upload", "/api/upload", "/api/v1/upload"} {
			mux.HandleFunc(route, handleUpload)
		}
		serverInst = &http.Server{Addr: addr, Handler: mux}
		go func() {
			logger.Info("pcap upload server listening", "addr", addr, "dir", dir)
			if err := serverInst.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("pcap upload server failed", "error", err.Error())
			}
		}()
	})
	return startErr
}

func handleUpload(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, uploadResponse{Message: "method not allowed", Error: "method not allowed"})
		return
	}
	if err := req.ParseMultipartForm(512 << 20); err != nil {
		writeJSON(rw, http.StatusBadRequest, uploadResponse{Message: "invalid multipart request", Error: err.Error()})
		return
	}
	clientID := strings.TrimSpace(req.FormValue("client_id"))
	if clientID == "" {
		clientID = "unknown"
	}
	var file io.ReadCloser
	var header *multipart.FileHeader
	var err error
	for _, field := range []string{"file", "pcap", "upload"} {
		file, header, err = req.FormFile(field)
		if err == nil {
			break
		}
	}
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, uploadResponse{Message: "missing file field", Error: err.Error()})
		return
	}
	defer file.Close()
	filename := fmt.Sprintf("%s_%s", sanitizeForFilename(clientID), sanitizeForFilename(header.Filename))
	fullPath := filepath.Join(uploadDir, filename)
	out, err := os.Create(fullPath)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, uploadResponse{Message: "failed to create file", Error: err.Error()})
		return
	}
	defer out.Close()
	size, err := io.Copy(out, file)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, uploadResponse{Message: "failed to save file", Error: err.Error()})
		return
	}
	pcapstore.EnqueueFile(fullPath, clientID)
	writeJSON(rw, http.StatusOK, uploadResponse{Message: "ok", Filename: filename, Size: size})
}

func sanitizeForFilename(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "..", "")
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, value)
	if value == "" {
		return "upload"
	}
	return value
}

func writeJSON(rw http.ResponseWriter, status int, value any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(value)
}
