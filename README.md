# BOKALBS VPN

A private "virtual LAN" for friends in different places. Install it on your Windows PCs, join the same network, and the computers act as if they were plugged into the same router:

- **Play LAN games together** – Warcraft III, StarCraft, Age of Empires, Minecraft LAN worlds and similar games find each other through LAN broadcasts, which BOKALBS VPN forwards.
- **Share files** – share a folder from inside the app with one click, or use normal Windows file sharing (`\\10.77.0.2`, "Map network drive").
- **No account, no third-party service** – one friend hosts the network from the app, or you run the small server on a VPS or Raspberry Pi.
- **Encrypted** – everything is end-to-end encrypted with modern cryptography (X25519, ChaCha20-Poly1305, Argon2id).
- **Fast** – PCs connect **directly to each other** (UDP hole punching) whenever possible, and fall back to relaying through the host.

## Download and install

1. Open the [Actions tab](../../actions/workflows/build.yml) and pick the latest successful run, or go to [Releases](../../releases) once you have tagged a version.
2. Download **BOKALBS-VPN-Setup-x.y.z.exe** and run it. (Windows 10/11, 64-bit.)
3. Start **BOKALBS VPN** from the Start menu. It asks for administrator rights because it creates a virtual network adapter.

Windows SmartScreen may warn about an unknown publisher, because the installer is not code-signed. Click **More info → Run anyway**.

## How to use it

One person **hosts**, everyone else **joins**.

### Host (one friend)

1. Choose **Host a network**, enter a nickname, a network name and a password (6+ characters), then click **Start hosting**.
2. The app tries to open UDP port **47820** on your router automatically (UPnP). If it can't, add a port-forwarding rule on the router: **UDP 47820 → this PC**.
3. Click **Copy invite** and send it to your friends. Tell them the password separately.

### Join (everyone else)

1. Choose **Join a network** and enter the host's address (for example `203.0.113.7:47820`), the network name and the password.
2. Click **Join network**. Your VPN address appears (for example `10.77.0.3`), and you see the other players in the list. **direct** means a peer-to-peer connection. **via server** means traffic goes through the host. Both work.

### Warcraft III

1. Everyone connects to the VPN first.
2. Start Warcraft III → **Local Area Network**.
3. One player creates a game. The others see it in their LAN list and join.

If a game does not show up: restart the game after connecting, allow the game through Windows Firewall, and close other VPN tools (Hamachi, Radmin VPN, ZeroTier) while you play. They compete for LAN broadcasts.

### Sharing files

- **Built-in share:** in **Share a folder**, pick a folder and tick **Share this folder while connected**. Friends click **Files** next to your name to browse and download (read-only). The share is reachable only through the VPN.
- **Windows file sharing:** share a folder in Windows (right-click → Properties → Sharing). Friends open `\\<your VPN address>` or use **Map network drive** so it looks like a local drive. They sign in with a Windows user account of the sharing PC.

## Hosting on a VPS / Raspberry Pi (optional)

If nobody can open a port at home, for example because the internet provider uses CGNAT, run the server on any always-on Linux machine. It needs no root rights:

```sh
# from the "BOKALBS-VPN-linux-cli" build artifact
./bokalbs-vpn-cli-linux-amd64 server -network friday-lan -password 'a-long-password' -leases leases.json
```

Open UDP port 47820 in the machine's firewall. Then everyone, including you, picks **Join a network** with `your-server-ip:47820`.

## How it works

```
   PC A (10.77.0.2)  ◄──── direct, encrypted UDP ────►  PC B (10.77.0.3)
          │                                                  │
          └──────────► server (host PC or VPS) ◄─────────────┘
              login, address assignment, broadcasts,
              relay when a direct path is impossible
```

- **Virtual adapter:** [Wintun](https://www.wintun.net/), the adapter used by WireGuard, appears in Windows as `BOKALBS-VPN` with an address in `10.77.0.0/24`. Only VPN addresses are routed through it. Your normal internet traffic is not affected.
- **Login:** the network password is stretched with Argon2id into a key. That key authenticates a fresh X25519 key exchange, so a wrong password never gets in and every session has new keys.
- **Direct connections:** the server tells each member how to reach the others, and the members punch through their NATs with encrypted pings. When that fails (symmetric NAT), traffic is relayed through the server.
- **LAN games:** Windows sends broadcasts (`255.255.255.255`, `10.77.0.255`) and multicast into the adapter, because the app gives the adapter the lowest interface metric. The server copies them to every member.
- **Firewall:** while connected, a Windows Firewall rule allows inbound traffic to your VPN address, and only from VPN addresses. The network is marked **Private** so file sharing works.

## Building from source

Requirements: Go 1.24+.

```sh
go test ./...                                                     # unit + end-to-end tests
GOOS=windows go build -ldflags "-H windowsgui" ./cmd/bokalbs-vpn  # desktop app
go build ./cmd/bokalbs-vpn-cli                                    # server / CLI
```

The Windows app also needs `wintun.dll` (amd64) from [wintun.net](https://www.wintun.net/) next to the exe. GitHub Actions (`.github/workflows/build.yml`) builds everything on every push: it downloads and verifies Wintun and produces the installer (Inno Setup) and a portable zip. Push a tag such as `v1.0.0` to publish a release.

| Path | Contents |
|---|---|
| `cmd/bokalbs-vpn` | Windows desktop app (WebView2 window; falls back to the browser) |
| `cmd/bokalbs-vpn-cli` | Headless server and client |
| `internal/proto` | Wire protocol and cryptography |
| `internal/server` | Coordination/relay server |
| `internal/client` | VPN client: handshake, NAT traversal, routing |
| `internal/tunnel` | Virtual adapter (Wintun on Windows, TUN on Linux) |
| `internal/app`, `internal/ui` | Desktop app logic and interface |
| `internal/share` | Read-only folder sharing over the VPN |
| `internal/portmap` | Automatic router port forwarding (UPnP) |
| `installer` | Inno Setup installer script |

## Limits

- IPv4 only inside the VPN.
- The app must stay open while you play. Closing the window disconnects.
- Up to 253 members per network (`/24`). The CLI server accepts `-subnet` for bigger networks.
