package bindings

import (
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
)

type ServiceService struct {
	ctrl    *controller.ServiceController
	emitter EventEmitter
}

func NewServiceService(ctrl *controller.ServiceController) *ServiceService {
	return &ServiceService{ctrl: ctrl}
}

func (s *ServiceService) SetEventEmitter(emitter EventEmitter) {
	s.emitter = emitter
}

func (s *ServiceService) emitSmokeProgress(event logic.SmokeProgressEvent) {
	if s.emitter != nil {
		s.emitter("service:smoke", event)
	}
}

func (s *ServiceService) emitSSHState(event logic.SSHConnectionState) {
	if s.emitter != nil {
		s.emitter("service:ssh", event)
	}
}

func (s *ServiceService) emitTerminalOutput(event logic.TerminalOutputEvent) {
	if s.emitter != nil {
		s.emitter("service:terminal", event)
	}
}

func (s *ServiceService) ChangeSSHPasswords(targetsInput, username, port string, oldPasswords []string, newPassword string, maxConcurrency int64) (*logic.SSHPasswordChangeResponse, error) {
	return s.ctrl.ChangeSSHPasswords(targetsInput, username, port, oldPasswords, newPassword, maxConcurrency)
}

// ============================================
// [已停用-UI已移除] 自检功能
// 保留后端代码供开发调试使用
// 如需恢复UI，取消下方注释即可
// ============================================
func (s *ServiceService) RunIntegrationSmoke() (*logic.SmokeReport, error) {
	return s.ctrl.RunIntegrationSmoke(s.emitSmokeProgress)
}

func (s *ServiceService) GetLatestSmokeReport() *logic.SmokeReport {
	return s.ctrl.GetLatestSmokeReport()
}

func (s *ServiceService) ConnectSSH(request logic.SSHConnectRequest) (*logic.SSHConnectionState, error) {
	state, err := s.ctrl.ConnectSSH(request)
	if state != nil {
		s.emitSSHState(*state)
	}
	return state, err
}

func (s *ServiceService) DisconnectSSH() *logic.SSHConnectionState {
	state := s.ctrl.DisconnectSSH()
	if state != nil {
		s.emitSSHState(*state)
	}
	return state
}

func (s *ServiceService) ReconnectSSH() (*logic.SSHConnectionState, error) {
	state, err := s.ctrl.ReconnectSSH()
	if state != nil {
		s.emitSSHState(*state)
	}
	return state, err
}

func (s *ServiceService) GetSSHConnectionState() *logic.SSHConnectionState {
	return s.ctrl.GetSSHConnectionState()
}

func (s *ServiceService) StartTerminal() (*logic.SSHConnectionState, error) {
	state, err := s.ctrl.StartTerminal(s.emitTerminalOutput, s.emitSSHState)
	if state != nil {
		s.emitSSHState(*state)
	}
	return state, err
}

func (s *ServiceService) StopTerminal() *logic.SSHConnectionState {
	state := s.ctrl.StopTerminal()
	if state != nil {
		s.emitSSHState(*state)
	}
	return state
}

func (s *ServiceService) SendTerminalInput(input string) error {
	return s.ctrl.SendTerminalInput(input)
}

func (s *ServiceService) ListRemoteDirectory(remotePath string) (*logic.RemoteFileList, error) {
	return s.ctrl.ListRemoteDirectory(remotePath)
}

func (s *ServiceService) ReadRemoteTextFile(remotePath string) (string, error) {
	return s.ctrl.ReadRemoteTextFile(remotePath)
}

func (s *ServiceService) WriteRemoteTextFile(remotePath, content string) error {
	return s.ctrl.WriteRemoteTextFile(remotePath, content)
}

func (s *ServiceService) CreateRemoteDirectory(remotePath string) error {
	return s.ctrl.CreateRemoteDirectory(remotePath)
}

func (s *ServiceService) CreateRemoteFile(remotePath string) error {
	return s.ctrl.CreateRemoteFile(remotePath)
}

func (s *ServiceService) DeleteRemoteEntry(remotePath string) error {
	return s.ctrl.DeleteRemoteEntry(remotePath)
}

func (s *ServiceService) RenameRemoteEntry(oldPath, newPath string) error {
	return s.ctrl.RenameRemoteEntry(oldPath, newPath)
}

func (s *ServiceService) UploadRemoteFileContent(remoteDir, filename, contentBase64 string) (*logic.FileTransferResult, error) {
	return s.ctrl.UploadRemoteFileContent(remoteDir, filename, contentBase64)
}

func (s *ServiceService) PickAndUploadLocalFiles(remoteDir string) ([]logic.FileTransferResult, error) {
	return s.ctrl.PickAndUploadLocalFiles(remoteDir)
}

func (s *ServiceService) DownloadRemoteFile(remotePath string) (*logic.FileTransferResult, error) {
	return s.ctrl.DownloadRemoteFile(remotePath)
}
