# I Wrote a Port Scanner in 136 Lines of Python — Here's What nmap Hides

I ran **probe** — my 136-line port scanner — against an old Metasploitable 2 VM, then ran nmap against the same target. The results agreed on every single port. That's the boring part. The interesting part is what you learn about TCP, threads, and security by writing the tool yourself instead of typing `nmap -sT` and calling it a day.

## The Three-Way Handshake You Never See

A TCP connect scan does one thing: it attempts the three-way handshake and reports success or failure.

```
SYN ──────>
<────── SYN-ACK
ACK ──────>
```

If the kernel completes that handshake, the port is open. That's it. There's no magic — just `connect_ex()`.

This is the key choice: `connect_ex()` returns an errno instead of throwing an exception. `connect()` raises `ConnectionRefusedError` immediately, which kills your scan function on the first closed port. `connect_ex()` gives `0` for open, a POSIX errno for anything else — closed, filtered, unreachable. You inspect the return value instead of catching exceptions, which is simpler at this layer.

That's the core of **probe**, stripped down:

```python
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
        s.close()
        return (port, False, "")
    except socket.timeout:
        if s: s.close()
        return (port, False, "")
    except ConnectionRefusedError:
        if s: s.close()
        return (port, False, "")
    except OSError:
        if s: s.close()
        return (port, False, "")
```

Two patterns to note:
- **`s = None` guard** — if `socket.socket()` itself fails, `s` is never assigned. Every close path checks `if s:` first, preventing `UnboundLocalError` or `AttributeError` on a half-constructed object.
- **Named exceptions only** — three specific handlers (`socket.timeout`, `ConnectionRefusedError`, `OSError`). A bare `except:` would swallow `KeyboardInterrupt` and make the scan unkillable mid-run.

Add a `ThreadPoolExecutor` wrapping this and you can scan 1024 ports in under 10 seconds.

## What I Learned Running This Against a Real Target

I pointed probe at Metasploitable 2 (a deliberately-vulnerable Linux VM) across ports 1-1024:

```
$ python probe.py -t 192.168.56.102 -p 1-1024 -f table
   21 OPEN  220 (vsFTPd 2.3.4)
   22 OPEN  SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
   23 OPEN
   25 OPEN  220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
   53 OPEN
   80 OPEN
  111 OPEN
  139 OPEN
  445 OPEN
  512 OPEN  Where are you?
  513 OPEN
  514 OPEN
```

12 open ports. Then I ran `nmap -sT` on the same box and got 23:

```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8009/tcp open  ajp13
8180/tcp open  unknown
```

**Every port in the overlapping range — 100% agreement.** Zero false positives, zero false negatives.

The mismatch is a range issue, not a logic issue. nmap's default "1000 ports" scan is a curated list that skips some low-numbered ports and includes popular high-numbered ones above 1024. My `-p 1-1024` sweep is a dumb contiguous range. The fix: extend the default range or switch to a curated list. But the socket logic is correct either way.

## The Version Strings Are the Real Payload

The banner grab is what separates recon from noise. Look at what the banner tells an attacker:

| Port | Banner | Maps To |
|------|--------|---------|
| 21 | `vsFTPd 2.3.4` | CVE-2011-0762 — backdoored, shell on :6200 |
| 22 | `OpenSSH_4.7p1 Debian-8ubuntu1` | Multiple vulns, username enumeration |
| 25 | `Postfix (Ubuntu)` | SMTP version known, spray/harvest |

Each banner is a CVE lookup table. `vsFTPd 2.3.4` in particular has a known backdoor: connect to port 21, send `USER letmein:)`, port 6200 opens a root shell. That's a three-second exploit chain from that banner string.

The defensive flip: strip or fake version strings. Apache has `ServerTokens Prod`, SSH has `VersionAddendum none`, and every FTP daemon lets you hide the version banner. Most default installs leave them on.

## Why the Thread Count Matters

The naive approach is "more threads = faster." In practice, past ~200 concurrent workers you hit the OS ephemeral port range and start getting `EADDRNOTAVAIL` errors — the kernel literally cannot allocate another source port for the outgoing SYN. Those connections fail immediately and ports report as closed when they're actually open.

```python
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = {
        executor.submit(scan_port, host, p, timeout): p
        for p in ports
    }
```

100 workers is the sweet spot for a standard Linux host. Go too low and the scan takes minutes. Go too high and accuracy drops — your scan gets *worse* by going faster. nmap's timing templates (`-T3`, `-T4`) manage this same trade-off internally with scan rates and retransmission timeouts.

---

The thing that got me: when I diffed probe output against nmap, I expected *some* difference — probe's a toy I wrote in an afternoon, nmap is two decades of engineering. They agreed on every port. That was the moment it clicked that a TCP connect scan is just a three-way handshake probe, and once you strip away the flags and timing templates, that's all it is. The second surprise was the banners. I knew services sent version strings, but seeing `vsFTPd 2.3.4` and immediately knowing there's a backdoor on port 6200 made the threat model real in a way reading about it never did.

---

## What nmap Hides

nmap is the gold standard — 20,000+ lines of C, 100+ flags, half a dozen scan types. That power has a cost: opacity. When a scan behaves unexpectedly, the debugging loop is guess a flag, re-run, interpret output, guess again.

probe is the inverse. 136 lines, four flags, one scan type you can hold in your head:

| nmap | probe |
|------|-------|
| 20k+ lines C | 136 lines Python |
| 100+ flags, 6 scan types | 4 flags, 1 scan type |
| You trust it or you don't | You can prove it |
| Debug by guessing | Debug by reading |
| Black box | Open book |

The argument: if you audit a target using a tool whose socket logic is a black box, you're trusting the tool author's assumptions about TCP — retransmission timeouts, scan rate, port selection. With probe, every `connect_ex` return code is right there. No magic, just the handshake, threaded, with named exception handlers on every failure path.

It's not a replacement for nmap. It's the debug version. You run nmap for speed, run probe when you need to understand *why*.

**Try it:** [github.com/keirsalterego/probe](https://github.com/keirsalterego/probe)

```bash
git clone https://github.com/keirsalterego/probe.git
cd probe
python probe.py --target scanme.nmap.org --ports 22,80,443 -f table
```

(Scan only hosts you own or have permission to test.)


