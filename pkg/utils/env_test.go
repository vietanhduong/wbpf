package utils

import (
	"os"
	"testing"
)

func Test_GetEnvOrDefault(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		if GetEnvOrDefault("test", "default") != "default" {
			t.Error("should be default")
		}
	})
	t.Run("env", func(t *testing.T) {
		os.Setenv("test", "env")
		if GetEnvOrDefault("test", "default") != "env" {
			t.Error("should be env")
		}
	})
}
