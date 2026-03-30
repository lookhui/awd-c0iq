package controller

import "awd-h1m-pro/internal/core/logic"

type FlagController struct {
	service *logic.FlagService
}

func NewFlagController(service *logic.FlagService) *FlagController {
	return &FlagController{service: service}
}

func (c *FlagController) FetchFlagsAndSave(pathTemplate string) ([]logic.FlagResult, error) {
	return c.service.GetFlagsFromShellAndSave(pathTemplate)
}

func (c *FlagController) FetchFlagsAndSaveWithShell(pathTemplate, shellType, urlPass, pass, postField, command string) ([]logic.FlagResult, error) {
	return c.service.GetFlagsFromShellAndSaveWithType(pathTemplate, logic.ShellType(shellType), urlPass, pass, postField, command)
}

func (c *FlagController) readTargets() ([]string, error) {
	return logic.LoadTargetsFromOutput()
}
