package bindings

import (
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
)

type DefenseService struct {
	ctrl *controller.DefenseController
}

func NewDefenseService(ctrl *controller.DefenseController) *DefenseService {
	return &DefenseService{ctrl: ctrl}
}

func (s *DefenseService) BackupWebRoot(targetsInput string) ([]string, error) {
	return s.ctrl.Backup(targetsInput)
}

func (s *DefenseService) FindShells(targetsInput string) ([]logic.ShellFinding, error) {
	return s.ctrl.FindShell(targetsInput)
}

func (s *DefenseService) InspectHost(targetsInput string) ([]string, error) {
	return s.ctrl.InspectHost(targetsInput)
}

func (s *DefenseService) HardenWebRoot(targetsInput string) ([]string, error) {
	return s.ctrl.HardenWebRoot(targetsInput)
}

func (s *DefenseService) MakeUploadDirsReadOnly(targetsInput string) ([]string, error) {
	return s.ctrl.MakeUploadDirsReadOnly(targetsInput)
}

func (s *DefenseService) HardenPHPConfig(targetsInput string) ([]string, error) {
	return s.ctrl.HardenPHPConfig(targetsInput)
}

func (s *DefenseService) DeploySimpleWAF(targetsInput string) ([]string, error) {
	return s.ctrl.DeploySimpleWAF(targetsInput)
}

func (s *DefenseService) BackupDatabase(targetsInput string) ([]string, error) {
	return s.ctrl.BackupDatabase(targetsInput)
}

func (s *DefenseService) ChangeDatabasePassword(targetsInput, password string) ([]string, error) {
	return s.ctrl.ChangeDatabasePassword(targetsInput, password)
}

func (s *DefenseService) RestoreWebFromBackup(targetsInput, path string) ([]string, error) {
	return s.ctrl.RestoreWebFromBackup(targetsInput, path)
}

func (s *DefenseService) RestoreDatabaseFromBackup(targetsInput, path string) ([]string, error) {
	return s.ctrl.RestoreDatabaseFromBackup(targetsInput, path)
}
