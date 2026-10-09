//go:build !windows

package ui

import (
	"errors"
	"os/exec"
	"runtime"
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
