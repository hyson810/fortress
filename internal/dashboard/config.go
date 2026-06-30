package dashboard

// Config controls the optional dashboard server.
type Config struct {
	Enabled         bool `yaml:"enabled"`
	Port            int  `yaml:"port"`
	RefreshInterval int  `yaml:"refresh_interval"` // milliseconds
}

// DefaultConfig returns the default dashboard configuration (disabled).
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		Port:            9091,
		RefreshInterval: 1000,
	}
}
