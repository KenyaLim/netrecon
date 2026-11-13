#!/usr/bin/env python3
"""
netrecon - a beginner-friendly network reconnaissance toolkit.

For learning and for auditing YOUR OWN networks only.
Only private (RFC 1918), loopback, and link-local addresses are allowed.
"""

import argparse
import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import sys

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 8080: "http-alt",
    8443: "https-alt",
}

ETHICS_NOTICE = (
    "NetRecon: use only on networks and machines you own or have\n"
    "written permission to test. Public addresses are refused.\n"
)


# ---------- helpers ----------

def is_allowed_address(ip):
    """Allow only private, loopback, or link-local addresses."""
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolve_target(target):
    """Turn a hostname or IP string into an IP address object."""
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        try:
            return ipaddress.ip_address(socket.gethostbyname(target))
        except socket.gaierror:
            sys.exit(f"[!] Could not resolve host: {target}")


def require_allowed(ip):
    if not is_allowed_address(ip):
        sys.exit(
            f"[!] Refusing to work with public address {ip}.\n"
            "    NetRecon only targets private, loopback, or link-local addresses."
        )


def parse_port_range(text):
    """Accept '80', '1-1024', or '22,80,443' and return a sorted list."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        sys.exit(f"[!] Invalid port numbers: {bad}")
    return sorted(ports)


def run_command(args):
    """Run a system command and return its stdout as text (or '')."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


# ---------- commands ----------

def cmd_info(_args):
    """Show local IP, default gateway, and interface addresses."""
    # Connecting a UDP socket does not send any packets. It only asks
    # the kernel which local address it would use to reach the internet.
    local_ip = "unknown"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        pass

    gateway = "unknown"
    route = run_command(["ip", "route", "show", "default"])
    match = re.search(r"default via (\S+)", route)
    if match:
        gateway = match.group(1)

    print(f"Hostname      : {socket.gethostname()}")
    print(f"Local IP      : {local_ip}")
    print(f"Default gateway: {gateway}")
    print("\nInterfaces:")
    print(run_command(["ip", "-brief", "address"]).rstrip() or "  (ip command not found)")


def ping_host(ip):
    """Return True if the host answers one ping."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def cmd_discover(args):
    """Ping sweep of a subnet to find live hosts."""
    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except ValueError:
        sys.exit(f"[!] Bad network: {args.network}  (example: 192.168.1.0/24)")

    require_allowed(network.network_address)

    if network.num_addresses > 256:
        sys.exit("[!] Please use a /24 or smaller (256 addresses max).")

    hosts = list(network.hosts())
    print(f"[*] Sweeping {network} ({len(hosts)} addresses)...")

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive.append(futures[future])

    alive.sort()
    print(f"[+] {len(alive)} host(s) responded:")
    for ip in alive:
        print(f"    {ip}")


def grab_banner(ip, port, timeout):
    """Some services send a greeting line (like SSH or FTP). Read it if so."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(128)
            return data.decode("utf-8", errors="replace").strip().splitlines()[0]
    except (OSError, IndexError):
        return ""


def check_port(ip, port, timeout):
    """TCP connect scan. Returns True if the port accepted the connection."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except OSError:
        return False


def cmd_scan(args):
    """TCP connect scan with service names and banners."""
    ip = resolve_target(args.target)
    require_allowed(ip)

    if args.ports:
        ports = parse_port_range(args.ports)
    else:
        ports = sorted(COMMON_PORTS)

    print(f"[*] Scanning {args.target} ({ip}) on {len(ports)} port(s)...")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_port, ip, p, args.timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                open_ports.append(futures[future])

    open_ports.sort()
    if not open_ports:
        print("[+] No open ports found.")
        return

    print(f"[+] {len(open_ports)} open port(s):")
    print(f"    {'PORT':<8}{'SERVICE':<12}BANNER")
    for port in open_ports:
        service = COMMON_PORTS.get(port, "unknown")
        banner = grab_banner(ip, port, args.timeout)
        print(f"    {port:<8}{service:<12}{banner[:60]}")


def cmd_listen(_args):
    """Show ports this machine is listening on (uses the ss tool)."""
    output = run_command(["ss", "-tuln"])
    if not output:
        sys.exit("[!] Could not run 'ss'. Install it with: sudo apt install iproute2")
    print(output.rstrip())


# ---------- CLI ----------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Beginner-friendly network reconnaissance toolkit (ethical use only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="show local IP, gateway, and interfaces")

    p_disc = sub.add_parser("discover", help="find live hosts on a subnet")
    p_disc.add_argument("network", help="subnet in CIDR form, e.g. 192.168.1.0/24")
    p_disc.add_argument("--threads", type=int, default=50)

    p_scan = sub.add_parser("scan", help="TCP port scan a host")
    p_scan.add_argument("target", help="IP or hostname on a private network")
    p_scan.add_argument("--ports", help="e.g. 80 or 1-1024 or 22,80,443")
    p_scan.add_argument("--threads", type=int, default=100)
    p_scan.add_argument("--timeout", type=float, default=0.5)

    sub.add_parser("listen", help="show this machine's listening ports")
    return parser


def main():
    print(ETHICS_NOTICE)
    args = build_parser().parse_args()
    commands = {
        "info": cmd_info,
        "discover": cmd_discover,
        "scan": cmd_scan,
        "listen": cmd_listen,
    }
    try:
        commands[args.command](args)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")


if __name__ == "__main__":
    main()