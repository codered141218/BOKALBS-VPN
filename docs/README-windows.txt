BOKALBS VPN - play LAN games and share files with friends over the internet
==========================================================================

QUICK START
-----------
One friend HOSTS the network, everyone else JOINS it.

The host:
  1. Open BOKALBS VPN, choose "Host a network".
  2. Type a nickname, a network name and a password, click "Start hosting".
  3. Send friends the network name and password ("Copy invite").
     No port forwarding is needed.

Everyone else:
  1. Open BOKALBS VPN, choose "Join a network".
  2. Leave "Server address" empty; enter the network name and password.
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
  - Check that the network name and password match exactly.
  - Friends connect through the routers automatically (hole punching). If the
    host's app warns about "symmetric NAT / CGNAT", that internet connection
    does not allow it. Then let another friend host, forward UDP port 47820
    to the host PC in the router, or run the server on a small VPS:
        bokalbs-vpn-cli server -network NAME -password PASS

Settings and logs: %APPDATA%\BOKALBS-VPN
Project page:      https://github.com/codered141218/BOKALBS-VPN
