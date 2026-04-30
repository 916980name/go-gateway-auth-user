package auth

type Config struct {
	Providers []ProviderConfig `yaml:"providers" json:"providers"`
}

type ProviderConfig struct {
	Type string `yaml:"type" json:"type"`
}
