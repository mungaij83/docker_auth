package utils

import (
	"fmt"
	"os/exec"
)

type ExtAuthzConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}


func (c *ExtAuthzConfig) Validate() error {
	if c.Command == "" {
		return fmt.Errorf("command is not set")
	}
	if _, err := exec.LookPath(c.Command); err != nil {
		return fmt.Errorf("invalid command %q: %s", c.Command, err)
	}
	return nil
}
