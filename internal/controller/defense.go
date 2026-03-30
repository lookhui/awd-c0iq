package controller

import (
	"awd-h1m-pro/internal/core/logic"
)

type DefenseController struct {
	service *logic.DefenseService
}

func NewDefenseController(service *logic.DefenseService) *DefenseController {
	return &DefenseController{service: service}
}

func (c *DefenseController) FindShell(targetsInput string) ([]logic.ShellFinding, error) {
	return c.service.FindShells(targetsInput)
}

func (c *DefenseController) HardenWebRoot(targetsInput string) ([]string, error) {
	return c.service.HardenWebRoot(targetsInput)
}

func (c *DefenseController) MakeUploadDirsReadOnly(targetsInput string) ([]string, error) {
	return c.service.MakeUploadDirsReadOnly(targetsInput)
}

func (c *DefenseController) HardenPHPConfig(targetsInput string) ([]string, error) {
	return c.service.HardenPHPConfig(targetsInput)
}

func (c *DefenseController) DeploySimpleWAF(targetsInput string) ([]string, error) {
	return c.service.DeploySimpleWAF(targetsInput)
}

func (c *DefenseController) InspectHost(targetsInput string) ([]string, error) {
	return c.service.InspectHost(targetsInput)
}

func (c *DefenseController) Backup(targetsInput string) ([]string, error) {
	return c.service.BackupWebRoot(targetsInput)
}

func (c *DefenseController) ChangeDatabasePassword(targetsInput, password string) ([]string, error) {
	return c.service.ChangeDatabasePassword(targetsInput, password)
}

func (c *DefenseController) BackupDatabase(targetsInput string) ([]string, error) {
	return c.service.BackupDatabase(targetsInput)
}

func (c *DefenseController) RestoreWebFromBackup(targetsInput, path string) ([]string, error) {
	return c.service.RestoreWebFromBackup(targetsInput, path)
}

func (c *DefenseController) RestoreDatabaseFromBackup(targetsInput, path string) ([]string, error) {
	return c.service.RestoreDatabaseFromBackup(targetsInput, path)
}
