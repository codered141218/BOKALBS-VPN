//go:build !windows

package ui

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func opener() string {
	if runtime.GOOS == "darwin" {
		return "open"
	}
	return "xdg-open"
}

// OpenURL opens a web page in the default browser.
func OpenURL(url string) error { return exec.Command(opener(), url).Start() }

func openURL(url string) error { return OpenURL(url) }

func openExplorer(path string) error {
	return errors.New("opening Windows shares is only supported on Windows; use smb:" + path)
}

func pickFolder() (string, error) {
	return "", errors.New("type the folder path")
}

func openPath(p string) error { return exec.Command(opener(), p).Start() }

func revealPath(p string) error { return openPath(filepath.Dir(p)) }

// pickFiles has no native dialog here; tests and the CLI pass paths directly.
func pickFiles() ([]string, error) {
	if v := os.Getenv("BOKALBS_PICK_FILES"); v != "" {
		return strings.Split(v, string(os.PathListSeparator)), nil
	}
	return nil, errors.New("choosing files is only supported on Windows")
}
