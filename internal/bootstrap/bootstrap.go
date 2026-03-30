package bootstrap

import (
	"context"

	"awd-h1m-pro/internal/app/bindings"
	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/controller"
	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/logger"
	"awd-h1m-pro/internal/netutil"
	"awd-h1m-pro/internal/pcapsearch"
	"awd-h1m-pro/internal/pcapserver"
	"awd-h1m-pro/internal/pcapstore"
	"awd-h1m-pro/internal/util"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type Container struct {
	app *application.App

	attackController    *controller.AttackController
	defenseController   *controller.DefenseController
	detectionController *controller.DetectionController
	monitorController   *controller.MonitorController
	flagController      *controller.FlagController
	configController    *controller.ConfigController
	serviceController   *controller.ServiceController

	attackService    *bindings.AttackService
	defenseService   *bindings.DefenseService
	detectionService *bindings.DetectionService
	monitorService   *bindings.MonitorService
	flagService      *bindings.FlagService
	configService    *bindings.ConfigService
	sshService       *bindings.ServiceService
	fileService      *bindings.FileService

	services []application.Service
}

func NewContainer() *Container {
	container := &Container{}
	container.initControllers()
	container.buildServices()
	return container
}

func (c *Container) initControllers() {
	attackLogic := logic.NewAttackService()
	serviceLogic := &logic.ServiceService{}
	defenseLogic := logic.NewDefenseService(serviceLogic)
	detectionLogic := logic.NewDetectionService()
	monitorLogic := logic.NewMonitorService(serviceLogic)
	flagLogic := logic.NewFlagService(attackLogic)

	c.attackController = controller.NewAttackController(attackLogic)
	c.defenseController = controller.NewDefenseController(defenseLogic)
	c.detectionController = controller.NewDetectionController(detectionLogic)
	c.monitorController = controller.NewMonitorController(monitorLogic)
	c.flagController = controller.NewFlagController(flagLogic)
	c.configController = controller.NewConfigController()
	c.serviceController = controller.NewServiceController(serviceLogic)
}

func (c *Container) buildServices() {
	c.attackService = bindings.NewAttackService(c.attackController)
	c.defenseService = bindings.NewDefenseService(c.defenseController)
	c.detectionService = bindings.NewDetectionService(c.detectionController)
	c.monitorService = bindings.NewMonitorService(c.monitorController)
	c.flagService = bindings.NewFlagService(c.flagController)
	c.configService = bindings.NewConfigService(c.configController)
	c.sshService = bindings.NewServiceService(c.serviceController)
	c.fileService = bindings.NewFileService()

	c.services = []application.Service{
		application.NewServiceWithOptions(c.attackService, application.ServiceOptions{Name: "AttackService"}),
		application.NewServiceWithOptions(c.defenseService, application.ServiceOptions{Name: "DefenseService"}),
		application.NewServiceWithOptions(c.detectionService, application.ServiceOptions{Name: "DetectionService"}),
		application.NewServiceWithOptions(c.monitorService, application.ServiceOptions{Name: "MonitorService"}),
		application.NewServiceWithOptions(c.flagService, application.ServiceOptions{Name: "FlagService"}),
		application.NewServiceWithOptions(c.configService, application.ServiceOptions{Name: "ConfigService"}),
		application.NewServiceWithOptions(c.sshService, application.ServiceOptions{Name: "ServiceService"}),
		application.NewServiceWithOptions(c.fileService, application.ServiceOptions{Name: "FileService"}),
	}
}

func (c *Container) AttachApp(app *application.App) {
	c.app = app
}

func (c *Container) App() *application.App {
	return c.app
}

func (c *Container) SetEventEmitter(emitter func(name string, data any)) {
	c.attackService.SetEventEmitter(emitter)
	c.monitorService.SetEventEmitter(emitter)
	c.sshService.SetEventEmitter(emitter)
}

func (c *Container) Services() []application.Service {
	return c.services
}

func (c *Container) InstallDefaultWindow() {
	if c.app == nil {
		return
	}
	c.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:              "main",
		Title:             "awd-c0iq",
		URL:               "/",
		Width:             1480,
		Height:            980,
		MinWidth:          1120,
		MinHeight:         760,
		DevToolsEnabled:   true,
		EnableDragAndDrop: true,
	})
}

func OnStartup(emitter func(name string, data any), ctx context.Context) error {
	if err := logger.Init(emitter, ctx); err != nil {
		return err
	}
	if err := config.InitConfig(); err != nil {
		return err
	}
	if err := util.EnsureDefaultOutputFiles(); err != nil {
		return err
	}
	_ = netutil.InitClient()
	if err := pcapstore.Init(util.JoinExePath("pcap.sqlite")); err != nil {
		logger.Warning("pcap db init failed", "error", err.Error())
	} else {
		pcapstore.StartProcessor()
	}
	if err := pcapsearch.Init(util.JoinExePath("bleve")); err != nil {
		logger.Warning("bleve init failed", "error", err.Error())
	}
	if err := pcapserver.Start(":18080", util.JoinExePath("pcap")); err != nil {
		logger.Warning("pcap server start failed", "error", err.Error())
	}
	logger.Success("awd-c0iq started successfully")
	return nil
}

func OnShutdown() error {
	logger.Info("awd-c0iq shutting down")
	return nil
}

func InstallWindows(app *application.App) {
	_ = app
}
