# EscapeRoom Lab — Digital Forensics and Malware Investigation

![tests](../../actions/workflows/tests.yml/badge.svg)

Project for **Cyber Security / Digital Forensics** (Academic Year 2026–2027), Department of Computer Engineering,
K. J. Somaiya School of Engineering, Mumbai.

We investigated the [CyberDefenders **EscapeRoom**](https://cyberdefenders.org/blueteam-ctf-challenges/escaperoom/) network-forensics lab:
a Linux VM was compromised through an SSH brute-force attack, infected with malware, and the malware hid itself with a kernel module.
This repository contains the **report**, the **findings**, and small **Python tools** that automate the analysis steps.

| | |
|---|---|
| **Team** | Sahil Mundhe (16010124180), Aryan Mahimkar (16010124165), Mohit Nagrecha (16010124184) |
| **Faculty** | Zaheed Shaikh |
| **Report** | [`docs/EscapeRoom_Lab_Report.pdf`](docs/EscapeRoom_Lab_Report.pdf) |
| **Video explanation** | [Google Drive](https://drive.google.com/file/d/1kasCk2Msp2Gk9iq0kRKoNA-LgJG9-ySu/view?usp=sharing) |
| **Date** | 18 October 2026 |

## Quick start

Needs only **Python 3.8+** (standard library, nothing to install).

```bash
git clone <this-repo-url>
cd EscapeRoom-Lab-Investigation
python demo.py                          # runs every tool on the sample data
python -m unittest discover -s tests -v # 12 unit tests
```

## What each tool does

| Script (`src/`) | Lab questions | What it does |
|-----------------|---------------|--------------|
| `ssh_failures.py` | Q2–Q4 | Counts SSH attempts, failures and successes from a Zeek `ssh.log` (same as the Zui query) |
| `audit_sudo.py` | Q5–Q6 | Finds cracked accounts that also have sudo rights; passwords are masked by default |
| `http_downloads.py` | Q7, Q8, Q16 | Shows the download tool (Wget), the 3 installation downloads and the 9 later requests |
| `hash_check.py` | Q9 | Computes MD5 / SHA-1 / SHA-256 of a file, optionally comparing with a known MD5 |
| `ps_check.py` | Q12 | Checks whether a path (default `/var/mail/mail`) is missing from `ps.log` |
| `decode_commands.py` | Q17 | Decodes `0x4e4f5000` and `0x52554e3a` into `NOP` and `RUN` |
| `scan_iocs.py` | – | Searches files for the indicators in `data/iocs.json` |
| `zeek_utils.py` | – | Shared reader for Zeek TSV logs and JSON-lines exports |

Example (`python src/ssh_failures.py data/sample/ssh.log`):

```
Total SSH attempts : 54
Successful         : 2
Failed (Q4 answer) : 52
```

## Results at a glance

| Stage | Finding |
|-------|---------|
| Entry | SSH brute force (likely Hydra) — 52 failed attempts, then a weak password worked |
| Credentials | `manager:forgot`, and `sean:spectre` (both sudo accounts; lab training credentials) |
| Download | Wget fetched 3 files; main malware MD5 `772b620736b760c1d736b1e6ba2f885b` |
| Persistence | Script rewrites `/etc/rc.local`; malware lives in `/var/mail` |
| Hiding | `/var/mail/mail` missing from `ps.log`; kernel module `sysmod.ko` |
| Malware | `requestFile`, IP `174.129.57.253`, 9 remote files, commands `NOP`, `RUN` |

Full detail: [`docs/findings.md`](docs/findings.md) · commands used: [`docs/commands.md`](docs/commands.md).

## Repository layout

```
EscapeRoom-Lab-Investigation/
├── README.md
├── demo.py                  run all tools on the sample data
├── src/                     analysis tools (Python)
├── tests/                   unit tests
├── data/
│   ├── iocs.json            indicators of compromise
│   └── sample/              SYNTHETIC logs + generator script
├── docs/
│   ├── EscapeRoom_Lab_Report.pdf
│   ├── findings.md          answers, timeline, annotated script
│   └── commands.md          commands and filters used
├── evidence/                put the real lab files here (git-ignored)
└── .github/workflows/       runs the tests on every push
```

## Using the real lab files

1. Download the artefacts from the [lab page](https://cyberdefenders.org/blueteam-ctf-challenges/escaperoom/).
2. Work **inside an isolated VM with networking off**. Never execute the downloaded files.
3. Put the files in `evidence/` (this folder is git-ignored) and follow [`docs/commands.md`](docs/commands.md).

## Important notes

- **Sample data is synthetic.** Files in `data/sample/` imitate the format and counts from the lab so the tools can be demonstrated.
  They are *not* the original CyberDefenders evidence.
- **Findings are reference-based.** The answers follow the published reference solution; see the limitations in the report.
- **Safety.** The tools only read files. PCAPs, password hashes, `shadow.log` and malware samples are excluded by `.gitignore`.
  The passwords shown are public lab training credentials.

## References


1. CyberDefenders, "EscapeRoom" — Blue Team CTF Challenges.
2. K. Kent et al., "Guide to Integrating Forensic Techniques into Incident Response," NIST SP 800-86, 2006.

## License

[MIT](LICENSE)
