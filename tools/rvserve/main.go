// Command rvserve runs local stand-ins for the public services used to join
// without port forwarding: an ntfy-compatible message server and a STUN
// server. It is a development tool for testing hole punching, e.g.:
//
//	rvserve -http :8080 -stun :3478
//	BOKALBS_RENDEZVOUS=http://127.0.0.1:8080 BOKALBS_STUN=127.0.0.1:3478 bokalbs-vpn-cli ...
package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/codered141218/bokalbs-vpn/internal/rendezvous/rvtest"
)

func main() {
	httpAddr := flag.String("http", ":8080", "ntfy-compatible HTTP listen address")
	stunAddr := flag.String("stun", ":3478", "STUN UDP listen address")
	flag.Parse()
	addr, err := net.ResolveUDPAddr("udp4", *stunAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	go rvtest.ServeSTUN(conn)
	log.Printf("STUN on %s, ntfy on %s", conn.LocalAddr(), *httpAddr)
	log.Fatal(http.ListenAndServe(*httpAddr, rvtest.NewNtfy()))
}
