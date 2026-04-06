# eBPF Security Sensor

A real-time Linux security sensor using eBPF to capture and analyze process behavior — plus a live browser dashboard deployable to Vercel.

![Dashboard Preview](docs/preview.png)

## What it does

- Attaches eBPF tracepoints to 14+ syscalls (execve, openat, socket, setuid, memfd_create, ptrace, and more)
- Builds anonymous **session fingerprints** from process ancestry + namespace inode + timing
- Scores sessions using **10 behavioral detection rules**
- Emits alerts when a session exceeds a threat score threshold (default: 100)
- Dumps full session chains as JSON on exit

## Repository structure

```
ebpf-sensor/
├── public/               ← Vercel static site (browser dashboard)
│   ├── index.html
│   ├── style.css
│   └── sensor.js         ← Simulation engine + UI
├── src/
│   └── sensor/
│       ├── ebpf_sensor.c      ← eBPF kernel program (BPF CO-RE)
│       └── sensor_loader.py   ← Python BCC loader (userspace)
├── vercel.json
└── README.md
```

## Quick start

### Dashboard (browser — no Linux required)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

Or just open `public/index.html` in any browser locally.

### Real sensor (Linux only, kernel ≥ 5.8, root required)

```bash
# 1. Install BCC
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# 2. Verify kernel version
uname -r

# 3. Run the sensor
cd src/sensor
sudo python3 sensor_loader.py

# 4. Options
sudo python3 sensor_loader.py --threshold 80 --output my_sessions.json
```

Press `Ctrl-C` to stop — session data is written to `sessions_dump.json`.

## Detection rules

| ID   | Signal                  | Syscalls            | Score |
|------|-------------------------|---------------------|-------|
| R001 | Sensitive file access   | openat              | +30   |
| R002 | Raw socket creation     | socket(AF_PACKET)   | +40   |
| R003 | Fileless execution      | memfd_create        | +70   |
| R004 | Log wiping              | ftruncate           | +60   |
| R005 | Namespace escape        | setns               | +50   |
| R006 | UID escalation          | setuid              | +80   |
| R007 | Directory enumeration   | getdents64          | +8    |
| R008 | ptrace attach           | ptrace              | +40   |
| R009 | Outbound connection     | connect             | +15   |
| R010 | Reverse shell listener  | bind + accept       | +25   |

## Attack chain patterns detected

- **Recon → Exfil**: `getdents64` → `openat(/etc/shadow)` → `socket` → `connect`
- **PrivEsc**: `openat(/etc/sudoers)` → `execve(sudo)` → `setuid(0)` → `execve(/bin/bash)`
- **Fileless**: `connect` → `memfd_create` → `execve(/proc/self/fd/N)`
- **Defense Evasion**: `ftruncate(/var/log/auth.log)` → `unlink`

## Session identity

Since there's no login token, sessions are derived from:

```
session_id = ktime_get_ns() XOR (pid << 32)
```

Session continuity is maintained through the `pid_tree` BPF map — forked children inherit their parent's session, keeping the full attack chain intact across `execve`/`fork` boundaries.

## Requirements

| Component   | Requirement               |
|-------------|---------------------------|
| Kernel      | 5.8+ (ring buffer support)|
| Architecture| x86_64                    |
| BCC         | `pip install bcc`         |
| Privileges  | Root (`sudo`)             |
| Python      | 3.8+                      |

## License

MIT — educational use. The eBPF C code is GPL-2.0 (kernel requirement).
