# probe

A threaded TCP port scanner with banner grab and three output formats. Study project for socket programming, concurrency, and network recon fundamentals.

```
python probe.py --target 127.0.0.1 --ports 22,80,443 --format table
```

## Quick start

```bash
git clone https://github.com/keirsalterego/probe.git
cd probe
python probe.py --target 127.0.0.1 --ports 1-1024
```

Requires Python 3.10+ (uses `dict[str, bool | str]` syntax). No external dependencies.

## Usage

```
python probe.py --target <host> --ports <spec> [--timeout <secs>] [--format <fmt>]
```

| Argument | Default | Description |
|---|---|---|
| `--target, -t` | — | Target hostname or IP (required) |
| `--ports, -p` | — | Port spec: `1-1024` or `22,80,443` or `1-1000,8080` |
| `--timeout` | `1.0` | Seconds to wait per connection |
| `--format, -f` | `json` | Output format: `json`, `csv`, or `table` |

### Output formats

**JSON** (default):
```json
{
  "22": {
    "open": true,
    "banner": "SSH-2.0-OpenSSH_10.3p1 Debian-4"
  }
}
```

**CSV**:
```
port,state,banner
22,open,SSH-2.0-OpenSSH_10.3p1 Debian-4
```

**Table**:
```
   22  OPEN  SSH-2.0-OpenSSH_10.3p1 Debian-4

1/1 ports open
```

## How it works

1. **`parse_ports()`** — expands port specs like `1-1024` into a deduplicated sorted list using a set. Rejects ports outside 1–65535 with `argparse.ArgumentTypeError`.
2. **`scan_port()`** — opens a TCP socket, sets a timeout, calls `connect_ex()`. Returns `(port, True, banner)` if the handshake completed (return code 0), or `(port, False, "")` otherwise. Three named exception handlers: `socket.timeout`, `ConnectionRefusedError`, `OSError`.
3. **`ThreadPoolExecutor`** — submits all port checks in parallel (100 workers by default). Each thread calls `scan_port()` independently.
4. **Banner grab** — on open ports, reads up to 1024 bytes via `s.recv(1024)`. Many services send a version string immediately on connect (SSH, HTTP, SMTP). Catches `socket.timeout` for services that don't.

## What a connect scan actually means

`connect_ex()` performs a full TCP three-way handshake:

```
SYN ──────>
<────── SYN-ACK
ACK ──────>
```

If the kernel completes that handshake, the port is open. This is the same mechanism `nmap -sT` uses. It's reliable but loud — every connection appears in the target's connection logs.

A filtered port (firewall drops without responding) hangs until the timeout fires. A closed port returns `ConnectionRefusedError` immediately.

## Security notes

- **Banner leaks** — the version strings in banners (`OpenSSH_10.3p1`) are what attackers map to CVEs. On production systems, hide or fake banners.
- **Loud scan** — a 100-thread sweep hits the target with 100 simultaneous connections. IDS/IPS will flag this. Real recon uses slower rates and longer timeouts.
- **Authorization required** — scan only hosts you own or have written permission to test.

## The wedge: what makes probe different from nmap

nmap is the gold standard — it does everything. That's also the problem. A 20,000-line C codebase is something you *run*, not something you *understand*. When a scan behaves unexpectedly, the debugging loop is: guess a flag, re-run, interpret output, guess again.

probe is the inverse. **136 lines of Python, start to finish.** Every line has exactly one job and you can read it all in a coffee break:

| nmap | probe |
|---|---|
| 20k+ lines of C | 136 lines of Python |
| 100+ flags | 4 flags |
| You trust it or you don't | You can prove it |
| Debug by guessing | Debug by reading |
| Black box | Open book |

The security argument: if you audit a target using a tool whose inner workings are a black box, you're trusting the tool author's assumptions about how TCP/IP works. With probe, you trace every `connect_ex` return code. There's no magic — just the TCP handshake, threaded.

**That's the wedge.** probe is not a replacement for nmap. It's a learning tool that turns into a debugging tool once you outgrow it. After you study the nmap source and understand what `-sS` and `-O` actually do at the packet level, you'll appreciate both tools more. But you start with the one you can hold in your head.

Read the full story on dev.to: [I Wrote a Port Scanner in 136 Lines of Python — Here's What nmap Hides](https://dev.to/keirsalterego/i-wrote-a-port-scanner-in-136-lines-of-python-heres-what-nmap-hides-2kg6)

## Edge cases handled

| Case | Behavior |
|---|---|
| Unreachable host | `OSError` → port marked closed |
| Bad port spec (`--ports abc`) | `argparse.ArgumentTypeError` with usage |
| Missing `--target` | argparse prints usage and exits |
| Timeout on banner read | Returns empty banner, port still marked open |
| Socket creation failure | `s = None` guard prevents `UnboundLocalError` |

## Development

```bash
ruff check .
mypy --strict probe.py
python probe.py --target 127.0.0.1 --ports 22
```
