package logic

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"sort"
	"strings"
	"time"

	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/logger"

	"github.com/pkg/sftp"
	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/crypto/ssh"
)

func (s *ServiceService) ConnectSSH(request SSHConnectRequest) (*SSHConnectionState, error) {
	request = normalizeSSHConnectRequest(request)
	if strings.TrimSpace(request.Host) == "" {
		return s.updateSSHFailureState(request, fmt.Errorf("ssh host is required"))
	}
	if strings.TrimSpace(request.Password) == "" {
		return s.updateSSHFailureState(request, fmt.Errorf("ssh password is required"))
	}

	client, err := dialSSH(request.Host, request.Port, request.Username, request.Password)
	if err != nil {
		return s.updateSSHFailureState(request, err)
	}

	oldClient := s.replaceSSHClient(client, request)
	if oldClient != nil {
		_ = oldClient.Close()
	}
	_ = config.Update(func(cfg *config.Config) {
		cfg.SSH.Host = request.Host
		cfg.SSH.Port = request.Port
		cfg.SSH.Username = request.Username
		cfg.SSH.Password = request.Password
	})
	logger.Info("ssh connected", "host", request.Host, "port", request.Port, "username", request.Username)
	return s.GetSSHConnectionState(), nil
}

func (s *ServiceService) DisconnectSSH() *SSHConnectionState {
	oldClient := s.replaceSSHClient(nil, SSHConnectRequest{})
	if oldClient != nil {
		_ = oldClient.Close()
	}
	s.mu.Lock()
	s.sshLastError = ""
	s.mu.Unlock()
	logger.Info("ssh disconnected")
	return s.GetSSHConnectionState()
}

func (s *ServiceService) ReconnectSSH() (*SSHConnectionState, error) {
	s.mu.RLock()
	request := s.sshRequest
	s.mu.RUnlock()
	if strings.TrimSpace(request.Host) == "" {
		cfg := config.Clone()
		request = SSHConnectRequest{
			Host:     cfg.SSH.Host,
			Port:     cfg.SSH.Port,
			Username: cfg.SSH.Username,
			Password: cfg.SSH.Password,
		}
	}
	return s.ConnectSSH(request)
}

func (s *ServiceService) GetSSHConnectionState() *SSHConnectionState {
	s.mu.RLock()
	request := s.sshRequest
	client := s.sshClient
	connectedAt := s.sshConnectedAt
	lastError := s.sshLastError
	s.mu.RUnlock()

	s.terminalMu.Lock()
	terminalActive := s.terminalActive
	s.terminalMu.Unlock()

	if strings.TrimSpace(request.Host) == "" {
		cfg := config.Clone()
		request = SSHConnectRequest{
			Host:     cfg.SSH.Host,
			Port:     cfg.SSH.Port,
			Username: cfg.SSH.Username,
		}
	}
	return &SSHConnectionState{
		Connected:    client != nil,
		Host:         request.Host,
		Port:         request.Port,
		Username:     request.Username,
		ConnectedAt:  connectedAt,
		LastError:    lastError,
		TerminalOpen: terminalActive,
	}
}

func (s *ServiceService) StartTerminal(onOutput func(TerminalOutputEvent), onState func(SSHConnectionState)) (*SSHConnectionState, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return nil, err
	}

	s.terminalMu.Lock()
	if s.terminalActive {
		s.terminalMu.Unlock()
		return s.GetSSHConnectionState(), nil
	}
	s.terminalMu.Unlock()

	session, err := client.NewSession()
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		_ = stdin.Close()
		_ = session.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		_ = stdin.Close()
		_ = session.Close()
		return nil, err
	}

	s.terminalMu.Lock()
	s.terminalSession = session
	s.terminalInput = stdin
	s.terminalActive = true
	s.terminalMu.Unlock()

	if onState != nil {
		onState(*s.GetSSHConnectionState())
	}
	if onOutput != nil {
		onOutput(TerminalOutputEvent{Kind: "status", Data: "terminal started", Timestamp: time.Now()})
	}

	go s.streamTerminalOutput(stdout, onOutput)
	go s.streamTerminalOutput(stderr, onOutput)
	go s.waitTerminal(session, onOutput, onState)

	return s.GetSSHConnectionState(), nil
}

func (s *ServiceService) SendTerminalInput(input string) error {
	s.terminalMu.Lock()
	writer := s.terminalInput
	active := s.terminalActive
	s.terminalMu.Unlock()
	if !active || writer == nil {
		return fmt.Errorf("terminal session is not active")
	}
	if !strings.HasSuffix(input, "\n") {
		input += "\n"
	}
	_, err := io.WriteString(writer, input)
	if err != nil {
		s.noteSSHOperationFailure(err)
	}
	return err
}

func (s *ServiceService) StopTerminal() *SSHConnectionState {
	session, input := s.clearTerminal()
	if input != nil {
		_ = input.Close()
	}
	if session != nil {
		_ = session.Close()
	}
	return s.GetSSHConnectionState()
}

func (s *ServiceService) ListRemoteDirectory(remotePath string) (*RemoteFileList, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	defer sftpClient.Close()

	currentPath := normalizeRemoteDirectory(remotePath)
	entries, err := sftpClient.ReadDir(currentPath)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	result := &RemoteFileList{
		CurrentPath: currentPath,
		ParentPath:  parentRemotePath(currentPath),
		Entries:     make([]RemoteFileEntry, 0, len(entries)),
	}
	for _, entry := range entries {
		result.Entries = append(result.Entries, RemoteFileEntry{
			Name:    entry.Name(),
			Path:    pathpkg.Join(currentPath, entry.Name()),
			IsDir:   entry.IsDir(),
			Size:    entry.Size(),
			Mode:    entry.Mode().String(),
			ModTime: entry.ModTime(),
		})
	}
	return result, nil
}

func (s *ServiceService) ReadRemoteTextFile(remotePath string) (string, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return "", err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return "", err
	}
	defer sftpClient.Close()

	file, err := sftpClient.Open(normalizeRemoteFilePath(remotePath))
	if err != nil {
		s.noteSSHOperationFailure(err)
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4<<20))
	if err != nil {
		s.noteSSHOperationFailure(err)
		return "", err
	}
	return string(data), nil
}

func (s *ServiceService) WriteRemoteTextFile(remotePath, content string) error {
	client, err := s.requireSSHClient()
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	defer sftpClient.Close()

	fullPath := normalizeRemoteFilePath(remotePath)
	if err := sftpClient.MkdirAll(pathpkg.Dir(fullPath)); err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	file, err := sftpClient.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, content)
	if err != nil {
		s.noteSSHOperationFailure(err)
	}
	return err
}

func (s *ServiceService) CreateRemoteDirectory(remotePath string) error {
	client, err := s.requireSSHClient()
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	defer sftpClient.Close()
	err = sftpClient.MkdirAll(normalizeRemoteDirectory(remotePath))
	if err != nil {
		s.noteSSHOperationFailure(err)
	}
	return err
}

func (s *ServiceService) CreateRemoteFile(remotePath string) error {
	return s.WriteRemoteTextFile(remotePath, "")
}

func (s *ServiceService) DeleteRemoteEntry(remotePath string) error {
	client, err := s.requireSSHClient()
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	defer sftpClient.Close()
	err = removeRemoteRecursive(sftpClient, normalizeRemoteFilePath(remotePath))
	if err != nil {
		s.noteSSHOperationFailure(err)
	}
	return err
}

func (s *ServiceService) RenameRemoteEntry(oldPath, newPath string) error {
	client, err := s.requireSSHClient()
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	defer sftpClient.Close()
	targetPath := normalizeRemoteFilePath(newPath)
	if err := sftpClient.MkdirAll(pathpkg.Dir(targetPath)); err != nil {
		s.noteSSHOperationFailure(err)
		return err
	}
	err = sftpClient.Rename(normalizeRemoteFilePath(oldPath), targetPath)
	if err != nil {
		s.noteSSHOperationFailure(err)
	}
	return err
}

func (s *ServiceService) UploadRemoteFileContent(remoteDir, filename, contentBase64 string) (*FileTransferResult, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(contentBase64)
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	defer sftpClient.Close()

	result, err := uploadRemoteBytes(sftpClient, normalizeRemoteDirectory(remoteDir), filepathBase(filename), data)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	return result, nil
}

func (s *ServiceService) PickAndUploadLocalFiles(remoteDir string) ([]FileTransferResult, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return nil, err
	}
	app := application.Get()
	if app == nil {
		return nil, fmt.Errorf("application is not ready")
	}
	paths, err := app.Dialog.OpenFile().
		SetTitle("选择要上传的本地文件").
		PromptForMultipleSelection()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	defer sftpClient.Close()

	results := make([]FileTransferResult, 0, len(paths))
	for _, localPath := range paths {
		data, readErr := os.ReadFile(localPath)
		if readErr != nil {
			return nil, readErr
		}
		item, uploadErr := uploadRemoteBytes(sftpClient, normalizeRemoteDirectory(remoteDir), filepathBase(localPath), data)
		if uploadErr != nil {
			s.noteSSHOperationFailure(uploadErr)
			return nil, uploadErr
		}
		item.LocalPath = localPath
		results = append(results, *item)
	}
	return results, nil
}

func (s *ServiceService) DownloadRemoteFile(remotePath string) (*FileTransferResult, error) {
	client, err := s.requireSSHClient()
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	defer sftpClient.Close()

	fullPath := normalizeRemoteFilePath(remotePath)
	file, err := sftpClient.Open(fullPath)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		s.noteSSHOperationFailure(err)
		return nil, err
	}

	app := application.Get()
	if app == nil {
		return nil, fmt.Errorf("application is not ready")
	}
	localPath, err := app.Dialog.SaveFile().
		SetFilename(pathpkg.Base(fullPath)).
		PromptForSingleSelection()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(localPath) == "" {
		return nil, fmt.Errorf("download cancelled")
	}
	if err := os.WriteFile(localPath, data, 0o644); err != nil {
		return nil, err
	}
	return &FileTransferResult{
		Name:       pathpkg.Base(fullPath),
		RemotePath: fullPath,
		LocalPath:  localPath,
		Size:       int64(len(data)),
	}, nil
}

func (s *ServiceService) updateSSHFailureState(request SSHConnectRequest, err error) (*SSHConnectionState, error) {
	request = normalizeSSHConnectRequest(request)
	s.mu.Lock()
	s.sshRequest = request
	s.sshLastError = err.Error()
	s.sshConnectedAt = time.Time{}
	s.sshClient = nil
	s.mu.Unlock()
	s.StopTerminal()
	logger.Warning("ssh connect failed", "host", request.Host, "port", request.Port, "error", err.Error())
	return s.GetSSHConnectionState(), err
}

func (s *ServiceService) replaceSSHClient(client *ssh.Client, request SSHConnectRequest) *ssh.Client {
	session, input := s.clearTerminal()
	if input != nil {
		_ = input.Close()
	}
	if session != nil {
		_ = session.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	oldClient := s.sshClient
	if client == nil {
		if strings.TrimSpace(request.Host) != "" {
			s.sshRequest = request
		}
		s.sshClient = nil
		s.sshConnectedAt = time.Time{}
		return oldClient
	}
	s.sshClient = client
	s.sshRequest = request
	s.sshConnectedAt = time.Now()
	s.sshLastError = ""
	return oldClient
}

func (s *ServiceService) requireSSHClient() (*ssh.Client, error) {
	s.mu.RLock()
	client := s.sshClient
	s.mu.RUnlock()
	if client == nil {
		return nil, fmt.Errorf("ssh is not connected")
	}
	return client, nil
}

func (s *ServiceService) clearTerminal() (*ssh.Session, io.WriteCloser) {
	s.terminalMu.Lock()
	defer s.terminalMu.Unlock()
	session := s.terminalSession
	input := s.terminalInput
	s.terminalSession = nil
	s.terminalInput = nil
	s.terminalActive = false
	return session, input
}

func (s *ServiceService) waitTerminal(session *ssh.Session, onOutput func(TerminalOutputEvent), onState func(SSHConnectionState)) {
	err := session.Wait()
	s.terminalMu.Lock()
	if s.terminalSession == session {
		s.terminalSession = nil
		s.terminalInput = nil
		s.terminalActive = false
	}
	s.terminalMu.Unlock()
	if err != nil && onOutput != nil {
		onOutput(TerminalOutputEvent{Kind: "error", Data: err.Error(), Timestamp: time.Now()})
	}
	if onState != nil {
		onState(*s.GetSSHConnectionState())
	}
}

func (s *ServiceService) streamTerminalOutput(reader io.Reader, onOutput func(TerminalOutputEvent)) {
	if onOutput == nil {
		io.Copy(io.Discard, reader)
		return
	}
	buffer := bufio.NewReaderSize(reader, 32*1024)
	chunk := make([]byte, 4096)
	for {
		count, err := buffer.Read(chunk)
		if count > 0 {
			onOutput(TerminalOutputEvent{
				Kind:      "output",
				Data:      string(chunk[:count]),
				Timestamp: time.Now(),
			})
		}
		if err != nil {
			if err != io.EOF {
				onOutput(TerminalOutputEvent{
					Kind:      "error",
					Data:      err.Error(),
					Timestamp: time.Now(),
				})
			}
			return
		}
	}
}

func (s *ServiceService) noteSSHOperationFailure(err error) {
	if err == nil {
		return
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "eof") &&
		!strings.Contains(message, "closed network connection") &&
		!strings.Contains(message, "broken pipe") &&
		!strings.Contains(message, "connection reset") {
		s.mu.Lock()
		s.sshLastError = err.Error()
		s.mu.Unlock()
		return
	}
	oldClient := s.replaceSSHClient(nil, SSHConnectRequest{})
	if oldClient != nil {
		_ = oldClient.Close()
	}
	s.mu.Lock()
	s.sshLastError = err.Error()
	s.mu.Unlock()
}

func normalizeSSHConnectRequest(request SSHConnectRequest) SSHConnectRequest {
	cfg := config.Clone()
	request.Host = strings.TrimSpace(request.Host)
	if request.Port == "" {
		request.Port = cfg.SSH.Port
	}
	if request.Port == "" {
		request.Port = "22"
	}
	if request.Username == "" {
		request.Username = cfg.SSH.Username
	}
	if request.Username == "" {
		request.Username = "root"
	}
	if request.Password == "" {
		request.Password = cfg.SSH.Password
	}
	request.Port = strings.TrimSpace(request.Port)
	request.Username = strings.TrimSpace(request.Username)
	return request
}

func normalizeRemoteDirectory(remotePath string) string {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		cfg := config.Clone()
		remotePath = strings.TrimSpace(cfg.SSH.Path)
	}
	if remotePath == "" {
		remotePath = "/"
	}
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	return pathpkg.Clean(remotePath)
}

func normalizeRemoteFilePath(remotePath string) string {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return normalizeRemoteDirectory(remotePath)
	}
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	return pathpkg.Clean(remotePath)
}

func parentRemotePath(remotePath string) string {
	remotePath = normalizeRemoteDirectory(remotePath)
	if remotePath == "/" {
		return "/"
	}
	return pathpkg.Dir(remotePath)
}

func filepathBase(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\\", "/")
	parts := strings.Split(value, "/")
	name := parts[len(parts)-1]
	if name == "" {
		return "upload.bin"
	}
	return name
}

func uploadRemoteBytes(client *sftp.Client, remoteDir, name string, data []byte) (*FileTransferResult, error) {
	if name == "" {
		name = "upload.bin"
	}
	if err := client.MkdirAll(remoteDir); err != nil {
		return nil, err
	}
	remotePath := pathpkg.Join(remoteDir, name)
	file, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return nil, err
	}
	return &FileTransferResult{
		Name:       name,
		RemotePath: remotePath,
		Size:       int64(len(data)),
	}, nil
}

func removeRemoteRecursive(client *sftp.Client, remotePath string) error {
	info, err := client.Stat(remotePath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return client.Remove(remotePath)
	}
	entries, err := client.ReadDir(remotePath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		childPath := pathpkg.Join(remotePath, entry.Name())
		if err := removeRemoteRecursive(client, childPath); err != nil {
			return err
		}
	}
	return client.RemoveDirectory(remotePath)
}
