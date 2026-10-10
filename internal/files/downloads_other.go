//go:build !windows

package files

import (
	"os"
	"path/filepath"
)

func downloadsFolder() string {
	if d := os.Getenv("BOKALBS_DOWNLOADS"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}
