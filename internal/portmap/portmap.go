// Package portmap asks the home router (via UPnP) to forward the server's
// UDP port, so friends can reach a network hosted on this PC without manual
// router configuration.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

type router interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string, intPort uint16, intClient string, enabled bool, desc string, lease uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	LocalAddr() net.IP
}

// Mapping is an active port forwarding on the router.
type Mapping struct {
	ExternalIP string
	Port       uint16
	r          router
	cancel     context.CancelFunc
}

const lease = 3600 // seconds; renewed every 20 minutes

// Map forwards UDP port on the router to this computer.
func Map(ctx context.Context, port uint16, description string) (*Mapping, error) {
	dctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var routers []router
	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(dctx); err == nil {
		for _, c := range cs {
			routers = append(routers, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(dctx); err == nil {
		for _, c := range cs {
			routers = append(routers, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(dctx); err == nil {
		for _, c := range cs {
			routers = append(routers, c)
		}
	}
	if len(routers) == 0 {
		return nil, errors.New("no UPnP router found (UPnP may be disabled on the router)")
	}
	var lastErr error
	for _, r := range routers {
		local := r.LocalAddr()
		if local == nil || local.To4() == nil {
			continue
		}
		if err := r.AddPortMappingCtx(dctx, "", port, "UDP", port, local.String(), true, description, lease); err != nil {
			lastErr = err
			continue
		}
		ext, _ := r.GetExternalIPAddressCtx(dctx)
		mctx, mcancel := context.WithCancel(context.Background())
		m := &Mapping{ExternalIP: ext, Port: port, r: r, cancel: mcancel}
		go m.renew(mctx, local.String(), description)
		return m, nil
	}
	if lastErr == nil {
		lastErr = errors.New("router has no usable IPv4 address")
	}
	return nil, fmt.Errorf("router refused port forwarding: %v", lastErr)
}

func (m *Mapping) renew(ctx context.Context, local, desc string) {
	t := time.NewTicker(20 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = m.r.AddPortMappingCtx(rctx, "", m.Port, "UDP", m.Port, local, true, desc, lease)
			cancel()
		}
	}
}

// Close removes the forwarding from the router.
func (m *Mapping) Close() {
	m.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.r.DeletePortMappingCtx(ctx, "", m.Port, "UDP")
}
