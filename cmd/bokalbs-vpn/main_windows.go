package main

import (
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/ui"
	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const windowTitle = "BOKALBS VPN"

func init() {
	// The window and WebView2 must stay on the main OS thread.
	runtime.LockOSThread()
}

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW     = user32.NewProc("FindWindowW")
	procShowWindow      = user32.NewProc("ShowWindow")
	procSetForegroundWn = user32.NewProc("SetForegroundWindow")
)

// singleInstance returns false (after focusing the existing window) when
// BOKALBS VPN is already running.
func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\BOKALBS-VPN-single-instance`)
	_, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		title, _ := windows.UTF16PtrFromString(windowTitle)
		if hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title))); hwnd != 0 {
			procShowWindow.Call(hwnd, 9) // SW_RESTORE
			procSetForegroundWn.Call(hwnd)
		} else {
			message("BOKALBS VPN is already running.", windows.MB_ICONINFORMATION)
		}
		return false
	}
	return true
}

func showWindow(u *ui.UI) {
	dataPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "BOKALBS-VPN", "WebView2")
	if os.Getenv("LOCALAPPDATA") == "" {
		dataPath = filepath.Join(config.Dir(), "WebView2")
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  dataPath,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  windowTitle,
			Width:  1060,
			Height: 760,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		// No WebView2 runtime: use the default browser instead.
		_ = ui.OpenURL(u.URL())
		message("BOKALBS VPN opened in your web browser.\n\n"+
			"Keep the browser tab open while playing. Use the Quit button on the page to close BOKALBS VPN.\n\n"+
			"Tip: install the Microsoft Edge WebView2 Runtime to get the normal app window.", windows.MB_ICONINFORMATION)
		<-u.Quit()
		return
	}
	defer w.Destroy()
	go func() {
		<-u.Quit()
		w.Dispatch(w.Terminate)
	}()
	w.Navigate(u.URL())
	w.Run()
}

func message(text string, flags uint32) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(windowTitle)
	_, _ = windows.MessageBox(0, t, c, flags)
}

func fatal(text string) { message(text, windows.MB_ICONERROR) }
