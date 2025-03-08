package config

import (
	"magitrickle/pkg/api/types"
)

type Rule struct {
	ID     types.ID `yaml:"id"`
	Name   string   `yaml:"name"`
	Type   string   `yaml:"type"`
	Rule   string   `yaml:"rule"`
	Enable bool     `yaml:"enable"`
}
