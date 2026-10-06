package app

import "kasa2onvif/internal/config"

// LoadConfig is a thin wrapper so main does not import the config package
// directly.
func LoadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}
