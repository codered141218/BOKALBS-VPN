package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// A fixed adapter GUID lets Windows recognise the network on every connect,
// so its "Private" network setting is remembered.
var adapterGUID = windows.GUID{Data1: 0x6b6f6b61, Data2: 0x6c62, Data3: 0x7376, Data4: [8]byte{0x70, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}

const firewallRule = "BOKALBS-VPN-members"

func openPlatform(addr netip.Prefix) (Device, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("administrator rights are required to create the VPN adapter")
	}
	if exe, err := os.Executable(); err == nil {
		if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil {
			return nil, errors.New("wintun.dll is missing next to the program; please reinstall BOKALBS VPN")
		}
	}
	tun.WintunTunnelType = "BOKALBS VPN"
	tun.WintunStaticRequestedGUID = &adapterGUID
	dev, err := tun.CreateTUN(AdapterName, MTU)
	if err != nil {
		return nil, fmt.Errorf("cannot create the VPN adapter: %w", err)
	}
	if err := configure(addr); err != nil {
		dev.Close()
		return nil, err
	}
	go makePrivate()
	return wrap(dev, removeFirewallRule), nil
}

func configure(addr netip.Prefix) error {
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	steps := [][]string{
		{"netsh", "interface", "ipv4", "set", "address", "name=" + AdapterName, "source=static",
			"address=" + addr.Addr().String(), "mask=" + mask, "gateway=none"},
		// Metric 1 makes this the preferred adapter for 255.255.255.255
		// broadcasts, which is how Warcraft III and other LAN games look for
		// games. Internet traffic is unaffected: we never add a default route.
		{"netsh", "interface", "ipv4", "set", "interface", "interface=" + AdapterName,
			"metric=1", "mtu=" + strconv.Itoa(MTU), "store=active"},
	}
	for _, s := range steps {
		var err error
		for try := 0; try < 10; try++ {
			if err = runHidden(s...); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			return err
		}
	}
	// Allow other members to reach this PC (file sharing, game hosting, ping),
	// but only on the VPN address and only from VPN addresses.
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
	if err := runHidden("netsh", "advfirewall", "firewall", "add", "rule", "name="+firewallRule,
		"dir=in", "action=allow", "profile=any", "enable=yes",
		"localip="+addr.Addr().String(), "remoteip="+addr.Masked().String()); err != nil {
		return fmt.Errorf("cannot add firewall rule: %w", err)
	}
	return nil
}

func removeFirewallRule() {
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
}

// makePrivate marks the VPN network as "Private" so Windows file sharing and
// network discovery work on it. Windows needs a few seconds to identify a new
// network, so retry for a while.
func makePrivate() {
	script := "Get-NetConnectionProfile -InterfaceAlias '" + AdapterName + "' -ErrorAction Stop | " +
		"Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop"
	for try := 0; try < 20; try++ {
		if runHidden("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script) == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func runHidden(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

const programRule = "BOKALBS-VPN-program"

// AllowProgram lets this program receive connections from the internet
// (friends reaching a network hosted here, and direct peer connections).
func AllowProgram() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+programRule, "program="+exe)
	return runHidden("netsh", "advfirewall", "firewall", "add", "rule", "name="+programRule,
		"dir=in", "action=allow", "profile=any", "enable=yes", "program="+exe)
}
