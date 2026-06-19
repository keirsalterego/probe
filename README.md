# probe

talks to ports. tells you which ones talk back.

```
python probe.py --target 192.168.56.10 --ports 1-1024
```

```
PORT   STATE   SERVICE
22     open    SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
80     open    HTTP/1.1 200 OK
445    open
```

## flags

| flag          | what it does                          |
|---------------|---------------------------------------|
| `--target`    | ip or hostname (required)             |
| `--ports`     | range like `1-1024` or list like `22,80,443` |
| `--threads`   | how many connections at once          |
| `--timeout`   | seconds to wait before giving up      |
| `-o`          | save output to a file                 |

default ports: 1-1024. default threads: 100.

## how it works

opens a socket, calls `connect_ex()`. if it returns 0, the port is open. threads make it fast.

nmap does this but with 15 years of polish. this one you can read in one sitting.

## edge cases

unreachable host, bad port range, missing target — all give you a clean message, not a traceback.
