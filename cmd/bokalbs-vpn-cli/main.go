// Command bokalbs-vpn-cli runs BOKALBS VPN without a window: a dedicated
// network server (for a VPS, Raspberry Pi or always-on PC) or a client.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/client"
	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/rendezvous"
	"github.com/codered141218/bokalbs-vpn/internal/server"
	"github.com/codered141218/bokalbs-vpn/internal/stun"
)

var version = "dev"

const usage = `BOKALBS VPN %s

Usage:
  bokalbs-vpn-cli server -network NAME -password PASS [-listen :47820] [-subnet 10.77.0.0/24] [-leases FILE] [-no-port-forwarding]
      Run a network server. Needs no administrator rights. Open/forward UDP port 47820,
      or use -no-port-forwarding so players can find it by network name and punch through.

  bokalbs-vpn-cli join [-server HOST:PORT] -network NAME -password PASS [-name NICK]
      Join a network from the command line (needs administrator/root rights).
      Without -server the host is found automatically.

  bokalbs-vpn-cli version

The password can also be given in the BOKALBS_PASSWORD environment variable.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	log.SetFlags(log.Ldate | log.Ltime)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:])
	case "join":
		err = runJoin(ctx, os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func password(p string) string {
	if p == "" {
		return os.Getenv("BOKALBS_PASSWORD")
	}
	return p
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", fmt.Sprintf(":%d", server.DefaultPort), "UDP address to listen on")
	network := fs.String("network", "", "network name")
	pass := fs.String("password", "", "network password")
	subnet := fs.String("subnet", server.DefaultSubnet, "virtual network (IPv4, /16 to /29)")
	leases := fs.String("leases", "", "file to remember assigned addresses across restarts")
	noPF := fs.Bool("no-port-forwarding", false, "let players find this server by network name (UDP hole punching)")
	_ = fs.Parse(args)
	rv := ""
	if *noPF {
		rv = rendezvous.URL()
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("invalid -subnet: %w", err)
	}
	srv, err := server.New(server.Config{
		Listen: *listen, Network: *network, Password: password(*pass), Subnet: prefix, LeaseFile: *leases, Logf: log.Printf,
		Rendezvous: rv, STUNServers: stun.Servers(),
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runJoin(ctx context.Context, args []string) error {
	settings := config.Load()
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	addr := fs.String("server", "", "server address host:port")
	network := fs.String("network", "", "network name")
	pass := fs.String("password", "", "network password")
	name := fs.String("name", settings.Nickname, "nickname")
	relay := fs.Bool("relay-only", false, "always relay through the server")
	_ = fs.Parse(args)
	if *addr != "" && !strings.Contains(*addr, ":") {
		*addr = fmt.Sprintf("%s:%d", *addr, server.DefaultPort)
	}
	if err := config.Save(settings); err != nil {
		log.Printf("cannot save device id: %v", err)
	}
	c, err := client.Start(ctx, client.Config{
		Server: *addr, Network: *network, Password: password(*pass), Name: *name,
		ClientID: settings.ClientID, RelayOnly: *relay, AppVersion: version, Logf: log.Printf,
		Rendezvous: rendezvous.URL(), STUNServers: stun.Servers(),
	})
	if err != nil {
		return err
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.Done():
			st := c.Status()
			if st.State == client.StateFailed {
				return fmt.Errorf("%s", st.Message)
			}
			return nil
		case <-ctx.Done():
			c.Stop()
			return nil
		case <-t.C:
			st := c.Status()
			if st.State != client.StateConnected {
				continue
			}
			var parts []string
			for _, p := range st.Peers {
				path := "relay"
				if p.Direct {
					path = fmt.Sprintf("direct %.0fms", p.RTTms)
				}
				parts = append(parts, fmt.Sprintf("%s=%s(%s)", p.Name, p.IP, path))
			}
			log.Printf("connected as %s; peers: %s", st.IP, strings.Join(parts, " "))
		}
	}
}
