//go:build !linux && !windows

package tunnel

import (
	"errors"
	"net/netip"
)

func openPlatform(addr netip.Prefix) (Device, error) {
	return nil, errors.New("the VPN adapter is only supported on Windows and Linux")
}
