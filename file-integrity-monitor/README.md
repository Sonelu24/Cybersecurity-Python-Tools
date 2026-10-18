# 🗂️ File Integrity Monitor

A Python tool that detects when files are **added, modified or deleted** in a folder. It saves a SHA-256 fingerprint ("baseline") of every file, then compares the folder against it later to spot tampering. This is the same idea behind tools like **Tripwire, OSSEC and Wazuh**.

## ✨ Features
- SHA-256 hashing of every file, including subfolders
- Detects **added**, **modified** and **deleted** files
- `watch` mode keeps checking and alerts the moment something changes
- Exit code `2` when changes are found, so it can be used in scripts or scheduled tasks
- Built-in `demo` that simulates an attack on a temporary folder
- Pure Python standard library, nothing to install

## 🎯 MITRE ATT&CK Mapping
| What it can catch | Technique | ID |
|---|---|---|
| Changed config files | Stored Data Manipulation | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) |
| Web shells dropped on a server | Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Deleted logs | Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |

## 🚀 Usage
Requires **Python 3.8+**.

```bash
# See it in action (simulated attack on a temporary folder)
python fim.py demo

# 1. Create a baseline of a folder
python fim.py baseline C:\path\to\folder

# 2. Later, check for changes
python fim.py check

# Or keep watching (checks every 5 seconds, Ctrl+C to stop)
python fim.py watch -i 5
```

| Command | Description |
|---|---|
| `baseline <folder>` | Hash every file and save the baseline |
| `check [folder]` | Compare the folder against the baseline once |
| `watch [folder]` | Keep checking and alert on new changes |
| `demo` | Run a simulated attack on a temporary folder |
| `-b`, `--baseline` | Baseline file to use (default: `baseline.json`) |
| `-i`, `--interval` | Seconds between checks in `watch` mode (default: 10) |

> **Tip:** In real use, keep the baseline file somewhere an attacker can't reach (read-only storage or another machine). If they can edit the baseline, they can hide their changes.

## 📊 Example Output
![File Integrity Monitor demo](demo.png)

```
=== File Integrity Monitor: demo ===

[1] Baseline created for a sample web server folder (3 files)

[2] Simulating an attacker...
    - modified config/settings.conf
    - dropped shell.php
    - deleted logs/access.log (covering tracks)

[3] Running integrity check...
[2026-10-18 13:50:52] [!!] INTEGRITY CHANGES DETECTED
     [ADDED]    shell.php
     [MODIFIED] config/settings.conf
     [DELETED]  logs/access.log
     Summary: 1 added, 1 modified, 1 deleted
```

## 🧠 What I Learned
- How cryptographic hashes act as file fingerprints: change one byte and the hash changes completely
- Host-based intrusion detection and why FIM is required by standards like **PCI DSS**
- Hashing large files in chunks to keep memory use low

## 🛣️ Future Improvements
- Sign the baseline with HMAC so tampering with it can be detected
- Send alerts by email or Discord/Slack webhook
- Ignore patterns (e.g. `*.tmp`, `cache/`)
