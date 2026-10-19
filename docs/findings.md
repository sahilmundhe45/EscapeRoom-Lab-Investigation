# Findings — EscapeRoom Lab

All answers follow the published reference solution for the lab. See
[`EscapeRoom_Lab_Report.pdf`](EscapeRoom_Lab_Report.pdf) for the full report with screenshots.

## Answers

| Q | Question | Answer | Tool in this repo |
|---|----------|--------|-------------------|
| Q1 | Service used to gain access | SSH | – (Wireshark) |
| Q2 | Attack type | Brute force | `ssh_failures.py` |
| Q3 | Likely attack tool | Hydra (inference) | – |
| Q4 | Failed attempts | 52 (of 54 attempts, 2 succeeded) | `ssh_failures.py` |
| Q5 | Credentials used | manager:forgot (lab account) | `audit_sudo.py` |
| Q6 | Other weak sudo account | sean:spectre (lab account) | `audit_sudo.py` |
| Q7 | Download tool | Wget | `http_downloads.py` |
| Q8 | Files downloaded | 3 | `http_downloads.py` |
| Q9 | Main malware MD5 | `772b620736b760c1d736b1e6ba2f885b` | `hash_check.py` |
| Q10 | Persistence file | `/etc/rc.local` | – |
| Q11 | Local file directory | `/var/mail` | – |
| Q12 | Missing from ps.log | `/var/mail/mail` | `ps_check.py` |
| Q13 | Concealment file | `sysmod.ko` | – |
| Q14 | Request function | `requestFile` | – (IDA/Ghidra) |
| Q15 | External IP starting with 17 | `174.129.57.253` | `scan_iocs.py` |
| Q16 | Files requested | 9 | `http_downloads.py` |
| Q17 | Server commands | NOP,RUN | `decode_commands.py` |

## What the downloaded shell script does (Q10, Q11, Q13)

This is the third downloaded file (`/d/3`), read as text and **never executed**.
Annotations are ours; the mechanism of the kernel module is *not* documented in the reference.

| Line in script | What it does |
|----------------|--------------|
| `mv 1 /var/mail/mail` and `chmod +x ...` | Moves downloaded file 1 (the malware) into `/var/mail` and makes it executable |
| `echo -e "...&\nsleep 1\npidof mail > /proc/dmesg\nexit 0" > /etc/rc.local` | Rewrites `/etc/rc.local` so the malware starts at every boot (**persistence**) |
| `nohup /var/mail/mail > /dev/null 2>&1&` | Starts the malware now, silently, in the background |
| `mv 2 /lib/modules/$(uname -r)/sysmod.ko` | Installs downloaded file 2 as a kernel module |
| `depmod -a`, `echo "sysmod" >> /etc/modules`, `modprobe sysmod` | Registers and loads the module, and loads it at every boot |
| `pidof mail > /proc/dmesg` | Passes the malware's process ID to the module (our inference: this is how it learns what to hide) |
| `rm 3` | Deletes the script itself to remove traces |

## Q17 — how the commands were decoded

The malware compares a value against two constants (`0x4e4f5000` and `0x52554e3a`).
Read as big-endian ASCII they spell `NOP` (+ a NUL byte) and `RUN` (+ `:`).
`src/decode_commands.py` repeats the CyberChef "From Hex" step.

## Attack timeline (logical order — the lab has no timestamps for these steps)

1. SSH is reachable on the VM.
2. Automated password guessing: 54 attempts, 52 fail.
3. A weak password succeeds and the attacker logs in.
4. Wget downloads three files over HTTP.
5. The script sets up `/etc/rc.local` persistence and loads `sysmod.ko`.
6. The malware disappears from `ps.log`.
7. The malware requests nine files from external servers (including `174.129.57.253`) and understands `NOP` / `RUN`.

## Indicators of compromise

See [`../data/iocs.json`](../data/iocs.json); search with `python src/scan_iocs.py <path>`.

## Mitigations

Use SSH keys and disable password logins · rate-limit and lock out repeated failures · strong unique passwords and minimal sudo rights ·
monitor `/etc/rc.local`, `/var/mail` and kernel-module loading · restrict outbound traffic · rebuild a compromised host from trusted media.
