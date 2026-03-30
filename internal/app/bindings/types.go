package bindings

import "time"

type EventEmitter func(name string, data any)

type TaskEventPayload struct {
	TaskID  string `json:"taskId"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type FileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}
