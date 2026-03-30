package controller

import (
	"fmt"
	"strconv"

	"awd-h1m-pro/internal/config"
)

type ConfigController struct{}

func NewConfigController() *ConfigController {
	return &ConfigController{}
}

func (c *ConfigController) GetConfig() *config.Config {
	return config.Clone()
}

func (c *ConfigController) buildConfigMap() map[string]any {
	cfg := config.Clone()
	return map[string]any{
		"version": cfg.Version,
		"ownIPs":  cfg.OwnIPs,
		"shell": map[string]any{
			"port":    cfg.Shell.Port,
			"pass":    cfg.Shell.Pass,
			"path":    cfg.Shell.Path,
			"file":    cfg.Shell.File,
			"method":  cfg.Shell.Method,
			"query":   cfg.Shell.Query,
			"payload": cfg.Shell.Payload,
			"timeout": cfg.Shell.Timeout,
			"proxy":   cfg.Shell.Proxy,
		},
		"ssh": map[string]any{
			"host":     cfg.SSH.Host,
			"port":     cfg.SSH.Port,
			"username": cfg.SSH.Username,
			"password": cfg.SSH.Password,
			"path":     cfg.SSH.Path,
		},
		"database": map[string]any{
			"host":     cfg.Database.Host,
			"port":     cfg.Database.Port,
			"username": cfg.Database.Username,
			"password": cfg.Database.Password,
			"name":     cfg.Database.Name,
		},
		"undeadHorse": map[string]any{
			"urlPass":  cfg.UndeadHorse.URLPass,
			"pass":     cfg.UndeadHorse.Pass,
			"filename": cfg.UndeadHorse.Filename,
		},
		"wormShell": map[string]any{
			"urlPass": cfg.WormShell.URLPass,
			"pass":    cfg.WormShell.Pass,
		},
	}
}

func (c *ConfigController) SaveConfig(values map[string]any) error {
	return config.Update(func(cfg *config.Config) {
		c.updateAllModuleConfigs(cfg, values)
	})
}

func (c *ConfigController) updateAllModuleConfigs(cfg *config.Config, values map[string]any) {
	if v, ok := values["ownIPs"].(string); ok {
		cfg.OwnIPs = v
	}
	if shellMap, ok := values["shell"].(map[string]any); ok {
		c.updateShellConfig(cfg, shellMap)
	}
	if sshMap, ok := values["ssh"].(map[string]any); ok {
		c.updateSSHConfig(cfg, sshMap)
	}
	if dbMap, ok := values["database"].(map[string]any); ok {
		if v, ok := dbMap["host"].(string); ok {
			cfg.Database.Host = v
		}
		if v, ok := dbMap["port"].(string); ok {
			cfg.Database.Port = v
		}
		if v, ok := dbMap["username"].(string); ok {
			cfg.Database.Username = v
		}
		if v, ok := dbMap["password"].(string); ok {
			cfg.Database.Password = v
		}
		if v, ok := dbMap["name"].(string); ok {
			cfg.Database.Name = v
		}
	}
	if undeadMap, ok := values["undeadHorse"].(map[string]any); ok {
		if v, ok := undeadMap["urlPass"].(string); ok {
			cfg.UndeadHorse.URLPass = v
		}
		if v, ok := undeadMap["pass"].(string); ok {
			cfg.UndeadHorse.Pass = v
		}
		if v, ok := undeadMap["filename"].(string); ok {
			cfg.UndeadHorse.Filename = v
		}
	}
	if wormMap, ok := values["wormShell"].(map[string]any); ok {
		if v, ok := wormMap["urlPass"].(string); ok {
			cfg.WormShell.URLPass = v
		}
		if v, ok := wormMap["pass"].(string); ok {
			cfg.WormShell.Pass = v
		}
	}
}

func (c *ConfigController) updateShellConfig(cfg *config.Config, shellMap map[string]any) {
	if v, ok := shellMap["port"].(string); ok {
		cfg.Shell.Port = v
	}
	if v, ok := shellMap["pass"].(string); ok {
		cfg.Shell.Pass = v
	}
	if v, ok := shellMap["path"].(string); ok {
		cfg.Shell.Path = v
	}
	if v, ok := shellMap["file"].(string); ok {
		cfg.Shell.File = v
	}
	if v, ok := shellMap["method"].(string); ok {
		cfg.Shell.Method = v
	}
	if v, ok := shellMap["query"].(string); ok {
		cfg.Shell.Query = v
	}
	if v, ok := shellMap["payload"].(string); ok {
		cfg.Shell.Payload = v
	}
	if v, ok := shellMap["proxy"].(string); ok {
		cfg.Shell.Proxy = v
	}
	switch value := shellMap["timeout"].(type) {
	case int64:
		cfg.Shell.Timeout = value
	case int:
		cfg.Shell.Timeout = int64(value)
	case float64:
		cfg.Shell.Timeout = int64(value)
	case string:
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			cfg.Shell.Timeout = parsed
		}
	}
}

func (c *ConfigController) updateSSHConfig(cfg *config.Config, sshMap map[string]any) {
	if v, ok := sshMap["host"].(string); ok {
		cfg.SSH.Host = v
	}
	if v, ok := sshMap["port"].(string); ok {
		cfg.SSH.Port = v
	}
	if v, ok := sshMap["username"].(string); ok {
		cfg.SSH.Username = v
	}
	if v, ok := sshMap["password"].(string); ok {
		cfg.SSH.Password = v
	}
	if v, ok := sshMap["path"].(string); ok {
		cfg.SSH.Path = v
	}
}

func (c *ConfigController) MustBuildConfigMap() map[string]any {
	return c.buildConfigMap()
}

func (c *ConfigController) String() string {
	return fmt.Sprintf("%v", c.buildConfigMap())
}
