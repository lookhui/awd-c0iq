package controller

import "awd-h1m-pro/internal/core/logic"

type ServiceController struct {
	service *logic.ServiceService
}

func NewServiceController(service *logic.ServiceService) *ServiceController {
	return &ServiceController{service: service}
}

func (c *ServiceController) ChangeSSHPasswords(targetsInput, username, port string, oldPasswords []string, newPassword string, maxConcurrency int64) (*logic.SSHPasswordChangeResponse, error) {
	return c.service.ChangeSSHPasswords(logic.SSHPasswordChangeParams{
		TargetsInput:   targetsInput,
		Username:       username,
		Port:           port,
		OldPasswords:   oldPasswords,
		NewPassword:    newPassword,
		MaxConcurrency: maxConcurrency,
	})
}

func (c *ServiceController) RunIntegrationSmoke(progress func(logic.SmokeProgressEvent)) (*logic.SmokeReport, error) {
	return c.service.RunIntegrationSmoke(progress)
}

func (c *ServiceController) GetLatestSmokeReport() *logic.SmokeReport {
	return c.service.GetLatestSmokeReport()
}

func (c *ServiceController) ConnectSSH(request logic.SSHConnectRequest) (*logic.SSHConnectionState, error) {
	return c.service.ConnectSSH(request)
}

func (c *ServiceController) DisconnectSSH() *logic.SSHConnectionState {
	return c.service.DisconnectSSH()
}

func (c *ServiceController) ReconnectSSH() (*logic.SSHConnectionState, error) {
	return c.service.ReconnectSSH()
}

func (c *ServiceController) GetSSHConnectionState() *logic.SSHConnectionState {
	return c.service.GetSSHConnectionState()
}

func (c *ServiceController) StartTerminal(onOutput func(logic.TerminalOutputEvent), onState func(logic.SSHConnectionState)) (*logic.SSHConnectionState, error) {
	return c.service.StartTerminal(onOutput, onState)
}

func (c *ServiceController) StopTerminal() *logic.SSHConnectionState {
	return c.service.StopTerminal()
}

func (c *ServiceController) SendTerminalInput(input string) error {
	return c.service.SendTerminalInput(input)
}

func (c *ServiceController) ListRemoteDirectory(remotePath string) (*logic.RemoteFileList, error) {
	return c.service.ListRemoteDirectory(remotePath)
}

func (c *ServiceController) ReadRemoteTextFile(remotePath string) (string, error) {
	return c.service.ReadRemoteTextFile(remotePath)
}

func (c *ServiceController) WriteRemoteTextFile(remotePath, content string) error {
	return c.service.WriteRemoteTextFile(remotePath, content)
}

func (c *ServiceController) CreateRemoteDirectory(remotePath string) error {
	return c.service.CreateRemoteDirectory(remotePath)
}

func (c *ServiceController) CreateRemoteFile(remotePath string) error {
	return c.service.CreateRemoteFile(remotePath)
}

func (c *ServiceController) DeleteRemoteEntry(remotePath string) error {
	return c.service.DeleteRemoteEntry(remotePath)
}

func (c *ServiceController) RenameRemoteEntry(oldPath, newPath string) error {
	return c.service.RenameRemoteEntry(oldPath, newPath)
}

func (c *ServiceController) UploadRemoteFileContent(remoteDir, filename, contentBase64 string) (*logic.FileTransferResult, error) {
	return c.service.UploadRemoteFileContent(remoteDir, filename, contentBase64)
}

func (c *ServiceController) PickAndUploadLocalFiles(remoteDir string) ([]logic.FileTransferResult, error) {
	return c.service.PickAndUploadLocalFiles(remoteDir)
}

func (c *ServiceController) DownloadRemoteFile(remotePath string) (*logic.FileTransferResult, error) {
	return c.service.DownloadRemoteFile(remotePath)
}
