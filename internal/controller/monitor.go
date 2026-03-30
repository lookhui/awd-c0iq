package controller

import (
	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/pcapsearch"
	"awd-h1m-pro/internal/pcapstore"
)

type MonitorController struct {
	service *logic.MonitorService
}

func NewMonitorController(service *logic.MonitorService) *MonitorController {
	return &MonitorController{service: service}
}

func (c *MonitorController) SearchTraffic(query string, page, size int64) ([]pcapsearch.SearchResult, error) {
	return pcapsearch.Search(query, int(page), int(size))
}

func (c *MonitorController) GetPcapDetail(id uint) (*pcapstore.PcapDetail, error) {
	return pcapstore.GetPcapDetail(id)
}

func (c *MonitorController) GetCaptureHistory(query string, limit int64) ([]logic.RemoteTrafficRecord, error) {
	return logic.GetCaptureHistory(query, int(limit))
}

func (c *MonitorController) StartRemoteCapture(request logic.RemoteCaptureRequest, progress func(logic.RemoteCaptureEvent)) (*logic.RemoteCaptureState, error) {
	return c.service.StartRemoteCapture(request, progress)
}

func (c *MonitorController) StopRemoteCapture(progress func(logic.RemoteCaptureEvent)) *logic.RemoteCaptureState {
	return c.service.StopRemoteCapture(progress)
}

func (c *MonitorController) GetRemoteCaptureState() *logic.RemoteCaptureState {
	return c.service.GetRemoteCaptureState()
}
