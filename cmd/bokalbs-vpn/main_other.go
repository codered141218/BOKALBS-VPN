//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/codered141218/bokalbs-vpn/internal/ui"
)

func singleInstance() bool { return true }

// showWindow opens the interface in the browser and runs until Quit or Ctrl+C.
func showWindow(u *ui.UI) {
	fmt.Println("BOKALBS VPN is running. Open this address in your browser:")
	fmt.Println(u.URL())
	_ = ui.OpenURL(u.URL())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-u.Quit():
	case <-sig:
	}
}

func fatal(text string) { fmt.Fprintln(os.Stderr, text) }
