package ui

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func shellOpen(target string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	file, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// OpenURL opens a web page in the default browser.
func OpenURL(url string) error { return shellOpen(url) }

func openURL(url string) error { return shellOpen(url) }

func openExplorer(path string) error {
	return exec.Command("explorer.exe", path).Start()
}

const pickScript = `
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true; ShowInTaskbar = $false}
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = 'Choose the folder to share with your VPN friends'
$d.ShowNewFolderButton = $true
if ($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }
`

func pickFolder() (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command", pickScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("could not open the folder picker; type the folder path instead")
	}
	return strings.TrimSpace(string(out)), nil
}

func openPath(p string) error { return shellOpen(p) }

func revealPath(p string) error {
	return exec.Command("explorer.exe", "/select,", p).Start()
}

const pickFilesScript = `
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true; ShowInTaskbar = $false}
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title = 'Choose files to send'
$d.Multiselect = $true
if ($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $d.FileNames | ForEach-Object { Write-Output $_ } }
`

func pickFiles() ([]string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command", pickFilesScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("could not open the file picker")
	}
	var paths []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			paths = append(paths, l)
		}
	}
	return paths, nil
}
