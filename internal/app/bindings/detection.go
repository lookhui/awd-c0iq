package bindings

import "awd-h1m-pro/internal/controller"

type DetectionService struct {
	ctrl *controller.DetectionController
}

func NewDetectionService(ctrl *controller.DetectionController) *DetectionService {
	return &DetectionService{ctrl: ctrl}
}

func (s *DetectionService) DetectHosts(targets string) (map[string]any, error) {
	return s.ctrl.DetectHosts(targets)
}
