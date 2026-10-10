// Command bokalbs-vpn is the BOKALBS VPN desktop application.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/app"
	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/ui"
)

// version is set at build time with -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	defer func() {
		if r := recover(); r != nil {
			crash := filepath.Join(config.Dir(), "crash.log")
			_ = os.MkdirAll(config.Dir(), 0o700)
			_ = os.WriteFile(crash, []byte(fmt.Sprintf("%s\npanic: %v\n\n%s", time.Now(), r, debug.Stack())), 0o600)
			fatal(fmt.Sprintf("BOKALBS VPN crashed: %v\n\nDetails were saved to %s", r, crash))
		}
	}()
	if !singleInstance() {
		return
	}
	a := app.New(version)
	a.Attention = attention
	a.Logf("BOKALBS VPN %s started", version)
	u, err := ui.Start(a)
	if err != nil {
		fatal("Cannot start the user interface: " + err.Error())
		return
	}
	defer u.Close()
	defer a.Disconnect()
	showWindow(u)
}
