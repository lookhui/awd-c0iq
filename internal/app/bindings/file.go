package bindings

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"awd-h1m-pro/internal/util"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type FileService struct{}

func NewFileService() *FileService {
	return &FileService{}
}

func (s *FileService) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	_ = ctx
	_ = options
	return nil
}

func (s *FileService) ServiceShutdown() error {
	return nil
}

func (s *FileService) ListOutputFiles() ([]FileInfo, error) {
	files := make([]FileInfo, 0)
	err := filepath.Walk(util.OutputDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || path == util.OutputDir() {
			return nil
		}
		files = append(files, FileInfo{
			Name:    info.Name(),
			Path:    path,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, err
}

func (s *FileService) ReadOutputFile(name string) (string, error) {
	path, err := resolveOutputPath(name)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *FileService) SaveOutputFile(name, content string) error {
	path, err := resolveOutputPath(name)
	if err != nil {
		return err
	}
	if err := util.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (s *FileService) ReadLogFile() (string, error) {
	entries, err := os.ReadDir(util.LogDir())
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	sort.Slice(entries, func(i, j int) bool {
		ii, _ := entries[i].Info()
		jj, _ := entries[j].Info()
		return ii.ModTime().After(jj.ModTime())
	})
	data, err := os.ReadFile(filepath.Join(util.LogDir(), entries[0].Name()))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func resolveOutputPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("output file path is empty")
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(util.OutputDir(), filepath.Clean(path))
	}
	if !util.IsSubPath(util.OutputDir(), path) {
		return "", os.ErrPermission
	}
	return path, nil
}
