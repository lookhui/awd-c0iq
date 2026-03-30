package bindings

import (
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/pcapsearch"
	"awd-h1m-pro/internal/pcapstore"
)

type MonitorService struct {
	ctrl    *controller.MonitorController
	emitter EventEmitter
}

func NewMonitorService(ctrl *controller.MonitorController) *MonitorService {
	return &MonitorService{ctrl: ctrl}
}

func (s *MonitorService) SetEventEmitter(emitter EventEmitter) {
	s.emitter = emitter
}

func (s *MonitorService) emitCapture(event logic.RemoteCaptureEvent) {
	if s.emitter != nil {
		s.emitter("monitor:capture", event)
	}
}

func (s *MonitorService) SearchTraffic(query string, page, size int64) ([]pcapsearch.SearchResult, error) {
	return s.ctrl.SearchTraffic(query, page, size)
}

func (s *MonitorService) GetPcapDetail(id uint) (*pcapstore.PcapDetail, error) {
	return s.ctrl.GetPcapDetail(id)
}

func (s *MonitorService) GetCaptureHistory(query string, limit int64) ([]logic.RemoteTrafficRecord, error) {
	return s.ctrl.GetCaptureHistory(query, limit)
}

func (s *MonitorService) StartRemoteCapture(request logic.RemoteCaptureRequest) (*logic.RemoteCaptureState, error) {
	return s.ctrl.StartRemoteCapture(request, s.emitCapture)
}

func (s *MonitorService) StopRemoteCapture() *logic.RemoteCaptureState {
	return s.ctrl.StopRemoteCapture(s.emitCapture)
}

func (s *MonitorService) GetRemoteCaptureState() *logic.RemoteCaptureState {
	return s.ctrl.GetRemoteCaptureState()
}
