package files

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func downloadsFolder() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, 0); err == nil && p != "" {
		return p
	}
	return filepath.Join(os.Getenv("USERPROFILE"), "Downloads")
}
