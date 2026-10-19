"""Generate SYNTHETIC sample logs so the tools can be tried without the real lab files.

These files only imitate the *format and counts* shown in the lab report
(54 SSH attempts / 2 successes, 3 + 9 HTTP downloads, etc.). They are NOT
the original CyberDefenders evidence.

Run:  python data/sample/generate_samples.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_TS = 1343510000.0   # arbitrary start time


def write(name, text):
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def zeek_header(path, fields):
    return ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
            f"#path\t{path}\n#fields\t" + "\t".join(fields) + "\n")


# ssh.log: 54 attempts from one source, the last two succeed
fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "auth_success"]
rows = []
for i in range(54):
    ok = "T" if i >= 52 else "-"
    rows.append("\t".join([f"{BASE_TS + i * 2.5:.6f}", f"CSYN{i:04d}", "23.20.23.147",
                           str(40000 + i * 7), "10.252.174.188", "22", "2", ok]))
write("ssh.log", zeek_header("ssh", fields) + "\n".join(rows) + "\n")

# http.log: 3 stage-1 downloads + 9 later requests across 4 servers
fields = ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "method", "host", "uri", "user_agent"]
reqs = [("23.20.23.147", f"/d/{n}") for n in (1, 2, 3)]
later = ["23.20.23.147", "23.22.228.174", "174.129.57.253", "23.21.35.128"]
order = [0, 1, 2, 3, 0, 1, 2, 3, 0]
reqs += [(later[k], f"/n/synthetic{j:02d}") for j, k in enumerate(order)]
rows = []
for i, (host, uri) in enumerate(reqs):
    rows.append("\t".join([f"{BASE_TS + 200 + i * 60:.6f}", f"CHTP{i:04d}", "10.252.174.188", host,
                           "80", "GET", host, uri, "Wget/1.13.4 (linux-gnu)"]))
write("http.log", zeek_header("http", fields) + "\n".join(rows) + "\n")

write("sudoers.log", """# Synthetic sudoers excerpt (format only)
Defaults\tenv_reset
root\tALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL
guest   ALL=(ALL) ALL
manager ALL=(ALL) ALL
sean    ALL=(ALL) ALL
roger   ALL=(ALL) ALL
pierce  ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
""")

# Mimics what `john` prints (passwords are the public lab answers; hashes are NOT included)
write("john_output.txt", """Using default input encoding: UTF-8
Loaded 11 password hashes with 11 different salts (sha512crypt)
Will run 4 OpenMP threads
forgot           (manager)
god              (gibson)
spectre          (sean)
""")

write("ps.log", """USER       PID %CPU %MEM COMMAND
root         1  0.0  0.1 /sbin/init
syslog     619  0.1  0.0 rsyslogd -c5
root       732  0.1  0.5 sshd: ubuntu [priv]
mysql      741  1.5  7.0 /usr/sbin/mysqld
root       777  0.0  0.2 /usr/sbin/apache2 -k start
www-data   779  0.0  0.3 /usr/sbin/apache2 -k start
root      1164  0.0  0.1 bash
root      1176  0.0  0.1 ps aux
""")
print("sample files written to", HERE)
