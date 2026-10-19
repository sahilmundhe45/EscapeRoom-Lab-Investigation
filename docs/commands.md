# Commands and filters used

`[R]` = documented in the reference solution, `[S]` = our suggestion (not from the reference).

| Tool | Command / filter / menu | Q | Origin |
|------|-------------------------|---|--------|
| Wireshark | Statistics → Protocol Hierarchy | Q1 | [R] |
| Wireshark | `ssh` or `tcp.port == 22`; Statistics → Conversations | Q1, Q2 | [S] |
| Wireshark | File → Export Objects → HTTP; Follow → HTTP Stream | Q7, Q9, Q10 | [R] |
| Zui | `_path=="ssh"` | Q4 | [R] |
| Zui | `_path=="ssh" \| count() by auth_success` | Q4 | [S] |
| Zui | `_path=="http" \| sort ts` | Q8 | [R] |
| John | `john --wordlist=/usr/share/wordlists/rockyou.txt shadow.log` | Q5, Q6 | [R] |
| John | `john --show shadow.log` | Q5, Q6 | [S] |
| NetworkMiner | Open PCAP → Files tab (MD5/SHA-256 shown in file details) | Q9 | [R] |
| Hashing | `md5sum <file>` or `python src/hash_check.py <file>` | Q9 | [S] |
| Shell | `grep -n "/var/mail" ps.log` or `python src/ps_check.py ps.log` | Q12 | [S] |
| Detect It Easy / UPX | Identify the packer, then unpack a **copy** | Q14 | [R] |
| IDA / Ghidra | Open `main`, find the call to `requestFile` | Q14–Q16 | [R] |
| CyberChef | From Hex on the two constants | Q17 | [R] |

## Running the tools in this repo on real lab files

```bash
# Export from Zui (or use Zeek logs) -> ssh.log / http.log, then:
python src/ssh_failures.py   evidence/ssh.log
python src/http_downloads.py evidence/http.log
python src/audit_sudo.py     evidence/john_output.txt evidence/sudoers.log
python src/ps_check.py       evidence/ps.log --path /var/mail/mail
python src/hash_check.py     evidence/<extracted_file> --expect-md5 772b620736b760c1d736b1e6ba2f885b
python src/scan_iocs.py      evidence/
```

Do this inside an isolated VM. The tools only *read* files; nothing is executed.
