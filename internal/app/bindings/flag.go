package bindings

import (
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
)

type FlagService struct {
	ctrl *controller.FlagController
}

func NewFlagService(ctrl *controller.FlagController) *FlagService {
	return &FlagService{ctrl: ctrl}
}

func (s *FlagService) FetchFlagsAndSave(pathTemplate string) ([]logic.FlagResult, error) {
	return s.ctrl.FetchFlagsAndSave(pathTemplate)
}

func (s *FlagService) FetchFlagsAndSaveWithShell(pathTemplate, shellType, urlPass, pass, postField, command string) ([]logic.FlagResult, error) {
	return s.ctrl.FetchFlagsAndSaveWithShell(pathTemplate, shellType, urlPass, pass, postField, command)
}
