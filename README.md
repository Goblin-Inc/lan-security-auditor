# LAN Security Auditor

> 🌐 **Language:** **English** | [Русский (README_Ru.md)](README_Ru.md)

«for authorized / educational use only»

A multi-threaded **Python** network scanner for discovering active hosts on a local network, analyzing open ports, and auditing network device security.

## ✨ Features
- 🌐 **Multi-Threaded ICMP/TCP Discovery** — rapidly identifies live hosts across a subnet (`ThreadPoolExecutor`).
- 🔎 **Service & Port Enumeration** — checks common services (HTTP/HTTPS, SSH, Telnet, FTP, SMB, SNMP, databases).
- 🛡️ **Web Admin & Router Auditing** — tests for default credentials and common misconfigurations on local network equipment.

## 🚀 Usage

```bash
pip install requests
python3 lan_auditor.py
```

## 📄 License
MIT © [Goblin-Inc](https://github.com/Goblin-Inc)
