

# Super Nmap

**Author:** Avi Twil
**Company:** Twil Industries

Super Nmap is a Python-based tool that allows you to scan multiple IP addresses using Nmap with full flexibility. You can pass any Nmap flags via CLI, and the results are displayed **in a color-coded, organized format** only after the scan completes. It supports:

* TCP/UDP port scanning
* Service version detection (`-sV`)
* OS detection (`-O`)
* Nmap scripts (`--script`)
* Port reasons (`--reason`)
* Full control of Nmap flags

The tool also displays a progress bar during scanning and a custom ASCII logo at startup.

---

## Requirements

* Python 3
* `python-nmap` module
* `tqdm` module
* `colorama` module
* `pyfiglet` module

---

## Installation

The tool is packaged as a Debian package (`Snmap.deb`). To install, run the provided `install.sh` script:

```bash
chmod +x install.sh
./install.sh
```

**What the script does:**

```bash
#!/bin/bash
echo "Installing Python3 - nmap..."
sudo apt install python3-nmap
echo "Installing package..."
sudo dpkg -i Snmap.deb
```

This will ensure `python3-nmap` is installed and then install the Super Nmap package system-wide.

After installation, you can run the tool simply as:

```bash
Snmap -f <ip_file> [-flags <NMAP_FLAGS>]
```

---

## Usage

```
Snmap -f <ip_file> [-flags <NMAP_FLAGS>]
```

### Options

* `-f <file>` — File containing list of IPs (one per line)
* `-flags <flags>` — Nmap flags to use (e.g., `-sS -sV -O --script vuln`)
* `-h, --help` — Show help menu

### Examples

Scan a list of IPs with default TCP SYN scan:

```bash
Snmap -f ips.txt
```

Scan with service version detection and Nmap vuln scripts:

```bash
Snmap -f ips.txt -flags -sS -sV --script vuln
```

Aggressive scan on specific ports:

```bash
Snmap -f ips.txt -flags -A -p 22,80,443 --open
```

Scan all hosts as online and skip host discovery:

```bash
Snmap -f ips.txt -flags -Pn -sV -O
```

---

## Features

* **Color-coded output**:

  * Open ports → Green
  * Filtered ports → Yellow
  * Closed ports → Red
  * Script output → Blue

* **Detailed results**: Includes ports, service names, versions, OS guesses, and reasons for port states.

* **Supports all Nmap flags**: Simply pass any Nmap argument after `-flags`.

* **Progress bar**: See real-time progress during scanning.

---

## License

MIT License

