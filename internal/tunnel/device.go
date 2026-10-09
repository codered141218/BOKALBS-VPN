// Package tunnel provides the virtual network adapter that makes the VPN
// look like a normal network card to Windows (and Linux).
package tunnel

import (
	"errors"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// AdapterName is the name of the network adapter shown in Windows.
const AdapterName = "BOKALBS-VPN"

// MTU of the virtual adapter. Encryption adds proto.Overhead plus IP/UDP
// headers; 1380 keeps every datagram below 1500 bytes, even over IPv6.
const MTU = 1380

// Device is a virtual network adapter carrying raw IPv4 packets.
type Device interface {
	// ReadPacket reads one outgoing IP packet into buf.
	ReadPacket(buf []byte) (int, error)
	// WritePacket injects an incoming IP packet.
	WritePacket(p []byte) error
	Close() error
}

// Open creates the virtual adapter and assigns it addr (e.g. 10.77.0.5/24).
// It needs administrator (root) rights.
func Open(addr netip.Prefix) (Device, error) {
	return openPlatform(addr)
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("device closed")

const offset = 16 // headroom wireguard-go's tun needs for virtio headers on Linux

// wgDevice adapts a wireguard-go tun.Device (which works on batches of
// packets) to the simpler one-packet-at-a-time Device interface.
type wgDevice struct {
	dev tun.Device

	rmu   sync.Mutex
	bufs  [][]byte
	sizes []int
	n, i  int

	wmu  sync.Mutex
	wbuf []byte

	closeOnce sync.Once
	onClose   func()
}

func wrap(dev tun.Device, onClose func()) *wgDevice {
	bs := dev.BatchSize()
	if bs < 1 {
		bs = 1
	}
	d := &wgDevice{dev: dev, bufs: make([][]byte, bs), sizes: make([]int, bs), wbuf: make([]byte, offset+65535), onClose: onClose}
	for i := range d.bufs {
		d.bufs[i] = make([]byte, offset+65535)
	}
	return d
}

func (d *wgDevice) ReadPacket(buf []byte) (int, error) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	for d.i >= d.n {
		n, err := d.dev.Read(d.bufs, d.sizes, offset)
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			return 0, err
		}
		d.n, d.i = n, 0
	}
	size := d.sizes[d.i]
	n := copy(buf, d.bufs[d.i][offset:offset+size])
	d.i++
	return n, nil
}

func (d *wgDevice) WritePacket(p []byte) error {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if len(p) > len(d.wbuf)-offset {
		return errors.New("packet too large")
	}
	n := copy(d.wbuf[offset:], p)
	_, err := d.dev.Write([][]byte{d.wbuf[:offset+n]}, offset)
	return err
}

func (d *wgDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		if d.onClose != nil {
			d.onClose()
		}
		err = d.dev.Close()
	})
	return err
}
