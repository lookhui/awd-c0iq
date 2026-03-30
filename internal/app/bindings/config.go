package bindings

import (
	"awd-h1m-pro/internal/config"
	"awd-h1m-pro/internal/controller"
)

type ConfigService struct {
	ctrl *controller.ConfigController
}

func NewConfigService(ctrl *controller.ConfigController) *ConfigService {
	return &ConfigService{ctrl: ctrl}
}

func (s *ConfigService) GetConfig() *config.Config {
	return s.ctrl.GetConfig()
}

func (s *ConfigService) UpdateShellConfig(port, pass, path, file, method, query, payload string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.Shell.Port = port
		cfg.Shell.Pass = pass
		cfg.Shell.Path = path
		cfg.Shell.File = file
		cfg.Shell.Method = method
		cfg.Shell.Query = query
		cfg.Shell.Payload = payload
	})
}

func (s *ConfigService) UpdateShellProxy(proxy string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.Shell.Proxy = proxy
	})
}

func (s *ConfigService) UpdateOwnIPs(ownIPs string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.OwnIPs = ownIPs
	})
}

func (s *ConfigService) UpdateSSHConfig(host, port, username, password, path string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.SSH.Host = host
		cfg.SSH.Port = port
		cfg.SSH.Username = username
		cfg.SSH.Password = password
		cfg.SSH.Path = path
	})
}

func (s *ConfigService) UpdateDatabaseConfig(host, port, username, password, name string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.Database.Host = host
		cfg.Database.Port = port
		cfg.Database.Username = username
		cfg.Database.Password = password
		cfg.Database.Name = name
	})
}

func (s *ConfigService) UpdateUndeadConfig(urlPass, pass, filename string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.UndeadHorse.URLPass = urlPass
		cfg.UndeadHorse.Pass = pass
		cfg.UndeadHorse.Filename = filename
	})
}

func (s *ConfigService) UpdateWormConfig(urlPass, pass string) error {
	return config.Update(func(cfg *config.Config) {
		cfg.WormShell.URLPass = urlPass
		cfg.WormShell.Pass = pass
	})
}

func (s *ConfigService) LoadConfig() (*config.Config, error) {
	return config.LoadConfig()
}

func (s *ConfigService) SaveConfig() error {
	return config.SaveConfig()
}
