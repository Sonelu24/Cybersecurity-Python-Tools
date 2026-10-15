# 🔍 SSH Log Analyzer

A Python tool that reads Linux SSH authentication logs (`/var/log/auth.log`), finds **brute-force login attempts**, and warns you when a suspicious IP **later logs in successfully**, which could mean an account was compromised.

## ✨ Features
- Counts failed SSH logins for each source IP
- Flags IPs that go over a threshold you can set
- Lists the usernames each attacker tried (e.g. `root`, `admin`, `oracle`)
- **Compromise alert:** catches a successful login from an IP that was brute-forcing
- Optional CSV report for further analysis
- Built-in `--demo` mode, so you don't need a real log to try it
- Pure Python standard library, nothing to install

## 🎯 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |

## 🚀 Usage
Requires **Python 3.8+**.

```bash
# Try it with the built-in sample log
python log_analyzer.py --demo

# Analyze a real log file
python log_analyzer.py /var/log/auth.log

# Custom threshold + CSV report
python log_analyzer.py /var/log/auth.log -t 10 -o report.csv
```

| Option | Description |
|---|---|
| `logfile` | Path to the auth log |
| `-t`, `--threshold` | Failed attempts before an IP is flagged (default: 5) |
| `-o`, `--output` | Save flagged IPs to a CSV file |
| `--demo` | Run against the built-in sample log |

## 📊 Example Output
```
=== SSH Log Analysis: built-in demo log ===
Total failed attempts : 13
Unique source IPs     : 3
Flagged IPs (>= 5)  : 2

IP Address         Fails  Usernames tried
------------------------------------------------------------
203.0.113.45           6  admin, oracle, root, test
198.51.100.7           6  bob, deploy, git, pi, ubuntu

[!!] ALERT: successful logins from flagged IPs (possible compromise):
     user 'bob' logged in from 198.51.100.7
```

## 🧠 What I Learned
- How SSH authentication events show up in Linux logs
- Writing regular expressions to pull structured data out of raw logs
- Building detection logic the way a SOC analyst triages alerts

## 🛣️ Future Improvements
- Time-window detection (e.g. 5 failures within 60 seconds)
- GeoIP lookup for attacker IPs
- Windows Event Log support (Event ID 4625)
