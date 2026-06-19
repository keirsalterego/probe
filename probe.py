import socket
import argparse
import json

def parse_args():
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
