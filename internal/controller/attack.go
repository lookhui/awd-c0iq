package controller

import (
	"path/filepath"

	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/util"
)

type AttackController struct {
	service *logic.AttackService
}

func NewAttackController(service *logic.AttackService) *AttackController {
	return &AttackController{service: service}
}

func (c *AttackController) TestShell(progress func(logic.ProgressEvent)) (string, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return "", err
	}
	return c.service.TestShellAsync(targets, progress), nil
}

func (c *AttackController) UploadUndeadHorse(urlPass, pass string, progress func(logic.ProgressEvent)) (string, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return "", err
	}
	return c.service.UploadUndeadHorseAsync(targets, urlPass, pass, progress), nil
}

func (c *AttackController) UploadMd5Horse(pass, postField string) ([]logic.CommandResult, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	return c.service.UploadMd5Horse(targets, pass, postField)
}

func (c *AttackController) UploadWormShell(urlPass, pass string) ([]logic.CommandResult, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	return c.service.UploadWormShell(targets, urlPass, pass)
}

func (c *AttackController) ExecCommandWithShell(command string) ([]logic.CommandResult, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	return c.service.ExecCommandForTargets(logic.ShellTypeNormal, targets, command)
}

func (c *AttackController) ExecCommandWithUndeadHorse(command string) ([]logic.CommandResult, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	return c.service.ExecCommandForTargets(logic.ShellTypeUndead, targets, command)
}

func (c *AttackController) ExecCommandWithMd5Horse(urlPass, pass, postField, command string) ([]logic.CommandResult, error) {
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	results := make([]logic.CommandResult, 0, len(targets))
	for _, target := range targets {
		result, cmdErr := c.service.ExecCommandViaMd5Horse(target, urlPass, pass, postField, command)
		if cmdErr != nil {
			result.Success = false
			result.Message = cmdErr.Error()
		}
		results = append(results, result)
	}
	return results, nil
}

func (c *AttackController) ExecCommandWithWormShell(urlPass, pass, command string) ([]logic.CommandResult, error) {
	_ = urlPass
	targets, err := c.ListTargets()
	if err != nil {
		return nil, err
	}
	return c.service.ExecCommandForTargets(logic.ShellTypeWorm, targets, command)
}

func (c *AttackController) TestShellWithTargets(targets []string, progress func(logic.ProgressEvent)) string {
	return c.service.TestShellAsync(util.UniqueSorted(targets), progress)
}

func (c *AttackController) ListTargets() ([]string, error) {
	return util.ReadLines(filepath.Join(util.OutputDir(), "target.txt"))
}

func (c *AttackController) SaveTargets(targets []string) error {
	return util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "target.txt"), util.UniqueSorted(targets))
}

func (c *AttackController) GetTaskStatus(taskID string) *logic.TaskState {
	return c.service.GetTaskStatus(taskID)
}

func (c *AttackController) GetShellTestStatus() (map[string]any, error) {
	successLines, _ := util.ReadLines(filepath.Join(util.OutputDir(), "success.txt"))
	errorLines, _ := util.ReadLines(filepath.Join(util.OutputDir(), "error.txt"))
	return map[string]any{
		"success": successLines,
		"error":   errorLines,
	}, nil
}
