package netutil

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/util"
)

func LogHTTPError(method, rawURL string, body []byte, statusCode int, err error) {
	if err == nil && statusCode == 0 {
		return
	}
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		bodyText = "-"
	}
	statusText := "-"
	if statusCode > 0 {
		statusText = fmt.Sprintf("%d", statusCode)
	}
	errText := "-"
	if err != nil {
		errText = err.Error()
	}
	entry := fmt.Sprintf(
		"[%s] [ERROR]\nURL: %s\nMethod: %s\nBody: %s\nStatus: %s\nError: %s\n%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		strings.TrimSpace(rawURL),
		strings.ToUpper(strings.TrimSpace(method)),
		bodyText,
		statusText,
		errText,
		strings.Repeat("-", 50),
	)
	_ = util.AppendText(filepath.Join(util.LogDir(), "http-error.log"), entry)
	logger.Error(
		"http request failed",
		"url", strings.TrimSpace(rawURL),
		"method", strings.ToUpper(strings.TrimSpace(method)),
		"body", bodyText,
		"status", statusCode,
		"error", errText,
	)
}
