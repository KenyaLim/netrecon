# NetRecon

A beginner-friendly network reconnaissance toolkit for Linux, with a
Cinnamon desktop panel widget.

NetRecon is built for learning networking and ethical hacking fundamentals.
It only works against private, loopback, and link-local addresses, so it
can be used to audit your own network and lab machines, not random
targets on the internet.

## Features

- `info`     Show your local IP, default gateway, and interface details
- `discover` Find live hosts on a local subnet (ping sweep)
- `scan`     TCP port scan with service names and banner grabbing
- `listen`   Show which ports this machine is listening on
- Cinnamon applet that shows your IP and listening ports in the panel

## Requirements

- Linux (tested on Linux Mint with Cinnamon)
- Python 3.8+
- `ping` and `ss` (both are installed by default on Mint)

## Quick start

    git clone https://github.com/KenyaLim/netrecon.git
    cd netrecon
    python3 netrecon.py info
    python3 netrecon.py discover 192.168.1.0/24
    python3 netrecon.py scan 192.168.1.1
    python3 netrecon.py listen

## Usage

    python3 netrecon.py info
    python3 netrecon.py discover 192.168.1.0/24
    python3 netrecon.py scan 127.0.0.1 --ports 1-1024
    python3 netrecon.py scan 192.168.1.10 --threads 100 --timeout 0.5
    python3 netrecon.py listen

Run `python3 netrecon.py -h` for full help.

## Cinnamon widget install

    mkdir -p ~/.local/share/cinnamon/applets
    cp -r netrecon@KenyaLim ~/.local/share/cinnamon/applets/

Then right-click your panel, choose Applets, find "NetRecon", and add it.
Click the icon to see the menu. It refreshes every 30 seconds.

To remove it, delete the folder:

    rm -rf ~/.local/share/cinnamon/applets/netrecon@KenyaLim

## Ethics and legal notice

- Only scan networks and machines you own or have written permission to test.
- NetRecon refuses public IP addresses on purpose.
- Unauthorized scanning can be illegal in many countries, even when it is
  only a port check.

## What you will learn

- How IP addressing and subnets work (CIDR notation)
- How ping sweeps and TCP connect scans work
- Why common ports matter (22 SSH, 80 HTTP, 443 HTTPS, 445 SMB, and more)
- How to use threads to speed up network tasks
- How to build a desktop applet with GJS (JavaScript) for Cinnamon

## Roadmap

- Save scan results to a file
- Add a simple HTML or text report
- Detect OS hints from banners
- Add unit tests

## License

MIT
