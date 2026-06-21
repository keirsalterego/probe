import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="probe - banner first JSON port scanner")

    parser.add_argument(
        "--target",
        "-t",
        required=True,
        type=str,
        help="hostname/IP of the target"
    )

    parser.add_argument(
        "--ports",
        "-p",
        required=True,
        type=str,
        help="ports to scan, e.g. 444, 777 or 1-1000"
    )

    parser.add_argument(
        "--timeout",
        "-tout",
        type=float,
        default=1.0,
        help="timeout per connection in seconds"
    )

    parser.add_argument(
        "--format",
        "-f",
        type=str,
        default="json",
        help="output format: JSON, CSV, or table"
    )
    return parser.parse_args()

def parse_ports(port_spec: str) -> list[int]:
    ## A set is for deduplication. for example if a user gave a port 80, 80, 80, 80,
    ## a set ensures that it only scans port 80 once. It also gives O(1) membership tests.
    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            for p in range(start, end + 1):
                ports.add(p)

        else:
            ports.add(int(part))

    for p in ports:
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(f"port {p} out of range (1-65535)")
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    s = None
    try:
        s = socket.socket()
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                banner = ""
            s.close()
            return (port, True, banner)
        else:
            s.close()
        return (port, False, "")
    except socket.timeout:
        if s:
            s.close()
        return (port, False, "")
    except ConnectionRefusedError:
        if s:
            s.close()
        return (port, False, "")
    except OSError:
        if s:
            s.close()
        return (port, False, "")


def main() -> None:
    args = parse_args()
    ports = parse_ports(args.ports)
    results: dict[int, tuple[bool, str]] = {}

    print(f"Scanning {args.target} on {len(ports)} ports...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(scan_port, args.target, p, args.timeout):
                p for p in ports
        }
        for future in futures:
            port, is_open, banner = future.result()
            results[port] = (is_open, banner)

    for port in sorted(results):
        is_open, banner = results[port]
        if is_open:
            banner_str = f"{banner}" if banner else ""
            print(f"{port:5d} OPEN{banner_str}")

    open_count = sum(1 for v in results.values() if v[0])
    print(f"\n{open_count}/{len(ports)} ports open")


if __name__ == "__main__":
    main()
