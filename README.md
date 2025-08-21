
````markdown
# Super Nmap

**Author:** Avi Twil
**Company:** Twil Industries
# 🚀 Snmap - Super Nmap Python Wrapper



**Snmap** is a **Python3-based wrapper for Nmap** that makes network scanning **fast, readable, and visually enhanced**.  
It supports single IPs, multiple IPs from files, or entire subnets, and can export results to **JSON**. Snmap highlights OS detection, port states, services, and Nmap script results with **color-coded terminal output**.

---

## ✨ Features

- ✅ Scan single IPs, multiple IPs, or entire subnets (CIDR notation)  
- ✅ Supports SYN, TCP Connect, UDP, Null, FIN, Xmas, ACK, Window, and Maimon scans  
- ✅ Service version detection and OS fingerprinting  
- ✅ Run Nmap scripts automatically and display results  
- ✅ Export results to JSON  
- ✅ Color-coded terminal output for easy reading  
- ✅ Detailed help menu and usage examples  
- ✅ Graceful error handling for missing files, no targets, or scan errors  

---

## 🛠 Installation

1. Clone the repository:

```bash
git clone https://github.com/avitwil/snmap.git
cd snmap
````

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

**Dependencies**:

* `python-nmap`
* `colorama`
* `tqdm`
* `pyfiglet`

3. Make the script executable (optional):

```bash
chmod +x snmap.py
```

---

## 📖 Usage

Basic syntax:

```bash
python snmap.py [options]
```

or if executable:

```bash
./snmap.py [options]
```

### 🎯 Target Selection

* `-f <file>` : Scan IPs from a file (one IP per line)
* `-t <ip>` : Scan a single IP
* `-ts <subnet>` : Scan a subnet in CIDR format (e.g., `192.168.1.0/24`)

### ⚡ Nmap Flags

* `-flags <NMAP_FLAGS>` : Pass custom Nmap flags, e.g., `-sS -sV -O --script vuln`
* Default scan type: `-sS` (SYN scan)

### 💾 Output Options

* `--json <file>` : Save results to a JSON file
* `-h, --help` : Show detailed help menu

---

## 🔎 Supported Nmap Scan Types

| Flag            | Description            |
| --------------- | ---------------------- |
| `-sS`           | TCP SYN scan (stealth) |
| `-sT`           | TCP connect scan       |
| `-sU`           | UDP scan               |
| `-sN, -sF, -sX` | Null, FIN, Xmas scans  |
| `-sA`           | TCP ACK scan           |
| `-sW`           | TCP Window scan        |
| `-sM`           | TCP Maimon scan        |

---

## 🖥 Service & OS Detection

| Flag             | Description                                        |
| ---------------- | -------------------------------------------------- |
| `-sV`            | Version detection for services                     |
| `-O`             | OS detection                                       |
| `--osscan-guess` | Aggressively guess OS                              |
| `-A`             | Aggressive scan (OS, version, scripts, traceroute) |

---

## 🔧 Other Useful Flags

| Flag                    | Description                            |
| ----------------------- | -------------------------------------- |
| `-p <ports>`            | Specify ports or ranges                |
| `--top-ports <num>`     | Scan top <num> ports                   |
| `--exclude-ports <num>` | Exclude ports from scan                |
| `-F`                    | Fast scan (fewer ports)                |
| `-Pn`                   | Treat all hosts as online              |
| `-n`                    | Skip DNS resolution                    |
| `-R`                    | Always resolve DNS                     |
| `-T0..T5`               | Timing template (0 slowest, 5 fastest) |
| `--script <scripts>`    | Run Nmap scripts (vuln, default, safe) |
| `--open`                | Show only open ports                   |
| `-v`                    | Increase verbosity                     |
| `-d`                    | Debug output                           |
| `--reason`              | Show reason a port is in a state       |
| `--version`             | Show Nmap version                      |

---

## 💡 Examples

* Scan multiple IPs from a file:

```bash
python snmap.py -f ips.txt
```

* Scan a single IP with version detection:

```bash
python snmap.py -t 192.168.1.10 -flags -sV
```

* Aggressive subnet scan, show only open ports:

```bash
python snmap.py -ts 192.168.1.0/24 -flags -A --open
```

* Scan a single IP and save results to JSON:

```bash
python snmap.py -t 10.0.0.5 --json results.json
```

---

## 📊 Output Format

Each host displays:

1. **Host IP**
2. **Operating System guesses** with accuracy
3. **Ports table**: protocol, port, state, service, product, version, reason
4. **Scripts output** (if any)

Example snippet:

```
Host: 192.168.1.10
  [ Operating System Guesses ]
    Windows 10 (95%)
  [ Ports ]
    Port 80/tcp: open | http Apache 2.4.41
    Port 22/tcp: filtered | ssh OpenSSH 7.9p1 | Reason: filtered
  [ Scripts ]
    80 - http-vuln-cve2017-5638: Vulnerable
```

---

## ⚠️ Errors & Troubleshooting

* **FileNotFoundError**: File specified with `-f` does not exist
* **No targets specified**: No `-f`, `-t`, or `-ts` argument provided
* **Scan errors**: Ensure Nmap is installed and run with sufficient privileges. Some scan types require root.

---

## 📝 License

This project is released under the **MIT License**.

---

## 👨‍💻 Author

**Avi Twil** (c) Ecomschool.co.il
Twil Industries

````
