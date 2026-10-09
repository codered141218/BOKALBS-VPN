BOKALBS VPN - play LAN games and share files with friends over the internet
==========================================================================

QUICK START
-----------
One friend HOSTS the network, everyone else JOINS it.

The host:
  1. Open BOKALBS VPN, choose "Host a network".
  2. Type a nickname, a network name and a password, click "Start hosting".
  3. Send friends the address shown under "Friends join with",
     plus the network name and password.

Everyone else:
  1. Open BOKALBS VPN, choose "Join a network".
  2. Enter the host's address, the network name and the password.
  3. Click "Join network". Your VPN address appears (e.g. 10.77.0.3).

WARCRAFT III AND OTHER LAN GAMES
--------------------------------
  - Connect the VPN first, then start the game.
  - Open "Local Area Network". One player creates a game; the others see it.
  - If Windows Firewall asks about the game, allow it.
  - Close Hamachi / Radmin / ZeroTier while playing.

SHARING FILES
-------------
  - "Share a folder" in the app: friends click "Files" next to your name
    and browse/download from that folder (read-only, only visible on the VPN).
  - Normal Windows sharing also works: \\<VPN address>, e.g. \\10.77.0.2
    (friends sign in with a Windows account of the PC that shares).

IF FRIENDS CANNOT CONNECT TO THE HOST
-------------------------------------
  - The host's router must let UDP port 47820 in. The app tries to do this
    automatically (UPnP). If that fails, add a port forwarding rule in the
    router: UDP 47820 -> the host PC.
  - Some internet providers (CGNAT) make hosting at home impossible. Then let
    another friend host, or run the server on a small VPS:
        bokalbs-vpn-cli server -network NAME -password PASS

Settings and logs: %APPDATA%\BOKALBS-VPN
Project page:      https://github.com/codered141218/BOKALBS-VPN
