package bindings

import (
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
)

type AttackService struct {
	ctrl    *controller.AttackController
	emitter EventEmitter
}

func NewAttackService(ctrl *controller.AttackController) *AttackService {
	return &AttackService{ctrl: ctrl}
}

func (s *AttackService) SetEventEmitter(emitter EventEmitter) {
	s.emitter = emitter
}

func (s *AttackService) emitProgress(event logic.ProgressEvent) {
	if s.emitter != nil {
		s.emitter("attack:progress", event)
		if event.Status == "done" {
			s.emitter("attack:complete", TaskEventPayload{TaskID: event.TaskID, Success: true, Message: event.Message})
		}
	}
}

func (s *AttackService) TestShell() (string, error) {
	return s.ctrl.TestShell(s.emitProgress)
}

func (s *AttackService) TestShellWithTargets(targets []string) string {
	return s.ctrl.TestShellWithTargets(targets, s.emitProgress)
}

func (s *AttackService) ListTargets() ([]string, error) {
	return s.ctrl.ListTargets()
}

func (s *AttackService) SaveTargets(targets []string) error {
	return s.ctrl.SaveTargets(targets)
}

func (s *AttackService) GetTaskStatus(taskID string) *logic.TaskState {
	return s.ctrl.GetTaskStatus(taskID)
}

func (s *AttackService) GetShellTestStatus() (map[string]any, error) {
	return s.ctrl.GetShellTestStatus()
}

func (s *AttackService) UploadUndeadHorse(urlPass, pass, _ string) (string, error) {
	return s.ctrl.UploadUndeadHorse(urlPass, pass, s.emitProgress)
}

func (s *AttackService) UploadMd5Horse(pass, postField, _ string) ([]logic.CommandResult, error) {
	return s.ctrl.UploadMd5Horse(pass, postField)
}

func (s *AttackService) UploadWormShell(urlPass, pass string) ([]logic.CommandResult, error) {
	return s.ctrl.UploadWormShell(urlPass, pass)
}

func (s *AttackService) ExecCommandWithShell(command string) ([]logic.CommandResult, error) {
	return s.ctrl.ExecCommandWithShell(command)
}

func (s *AttackService) ExecCommandWithUndeadHorse(command string) ([]logic.CommandResult, error) {
	return s.ctrl.ExecCommandWithUndeadHorse(command)
}

func (s *AttackService) ExecCommandWithMd5Horse(urlPass, pass, postField, command string) ([]logic.CommandResult, error) {
	return s.ctrl.ExecCommandWithMd5Horse(urlPass, pass, postField, command)
}

func (s *AttackService) ExecCommandWithWormShell(urlPass, pass, command string) ([]logic.CommandResult, error) {
	return s.ctrl.ExecCommandWithWormShell(urlPass, pass, command)
}
