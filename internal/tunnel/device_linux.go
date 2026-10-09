package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

func openPlatform(addr netip.Prefix) (Device, error) {
	name := "bokalbs0"
	dev, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return nil, fmt.Errorf("cannot create TUN device (are you root?): %w", err)
	}
	if real, err := dev.Name(); err == nil {
		name = real
	}
	cmds := [][]string{
		{"ip", "addr", "flush", "dev", name},
		{"ip", "addr", "add", addr.String(), "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(MTU), "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return wrap(dev, nil), nil
}
