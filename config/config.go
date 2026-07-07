package config

import (
	"errors"

	"github.com/spf13/viper"
)

type LocalConfig struct {
	AdminAPI     string `mapstructure:"admin_api"`
	NodeID       string `mapstructure:"node_id"` // public node identifier (safe to log)
	NodeToken    string `mapstructure:"node_token"`
	SyncInterval int    `mapstructure:"sync_interval"` // seconds
	LogLevel     string `mapstructure:"log_level"`     // log level for both logrus and xray-core: panic,fatal,error,warn,warning,info,debug,trace
}

func LoadLocalConfig(path string) (*LocalConfig, error) {
	v := viper.New()
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yml")
		v.AddConfigPath(".")
	}

	v.SetDefault("admin_api", "http://localhost:8080")
	v.SetDefault("node_id", "")
	v.SetDefault("node_token", "default_token")
	v.SetDefault("sync_interval", 60)
	v.SetDefault("log_level", "info")

	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, err
		}
		// Config file not found is acceptable if defaults/env are used
	}

	var cfg LocalConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
