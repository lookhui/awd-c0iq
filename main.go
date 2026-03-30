package main

import (
	"context"
	"embed"
	"log"
	"log/slog"

	"awd-h1m-pro/internal/bootstrap"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed assets/* frontend/bindings
var assets embed.FS

type AppLifecycleService struct {
	container *bootstrap.Container
}

func (s *AppLifecycleService) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	_ = options
	s.container.AttachApp(application.Get())
	emitter := func(name string, data any) {
		if app := s.container.App(); app != nil {
			app.Event.Emit(name, data)
		}
	}
	s.container.SetEventEmitter(emitter)
	if err := bootstrap.OnStartup(emitter, ctx); err != nil {
		return err
	}
	bootstrap.InstallWindows(s.container.App())
	return nil
}

func (s *AppLifecycleService) ServiceShutdown() error {
	return bootstrap.OnShutdown()
}

func main() {
	container := bootstrap.NewContainer()
	services := append([]application.Service{application.NewService(&AppLifecycleService{container: container})}, container.Services()...)
	app := application.New(application.Options{
		Name:        "awd-c0iq",
		Description: "AWD workstation rebuilt from the recovered Go binary",
		LogLevel:    slog.LevelWarn,
		Services:    services,
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	container.AttachApp(app)
	container.InstallDefaultWindow()
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
