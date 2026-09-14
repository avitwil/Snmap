#!/usr/bin/env python3
import argparse
import json
import re
import nmap
from colorama import Fore, Style, init
from tqdm import tqdm
import pyfiglet
import time
import sys

init(autoreset=True)

# ----------- Logo ----------- #
def print_logo():
    print(Fore.BLUE + pyfiglet.figlet_format("Twil-Industries", font="slant"))
    print(Fore.CYAN + "========================== Presents to you =========================\n")
    print(Fore.RED + pyfiglet.figlet_format(" Super Nmap ", font="slant"))
    print(Fore.GREEN + "================= Avi Twil (c) Ecomschool.co.il  student =================\n")

# ----------- Help Menu ----------- #
def help_menu():
    print(Fore.YELLOW + "USAGE: " + Fore.CYAN +
          "Snmap [-f <ip_file>] [-t <ip>] [-ts <subnet>] [-flags <NMAP_FLAGS>]\n")

    print(Fore.MAGENTA + "Target Options:")
    print(Fore.YELLOW + "  -f <file>            " + Fore.WHITE + "File containing list of IPs")
    print(Fore.YELLOW + "  -t <ip>              " + Fore.WHITE + "Single IP address to scan")
    print(Fore.YELLOW + "  -ts <subnet>         " + Fore.WHITE + "Subnet in CIDR format (e.g., 192.168.1.0/24)\n")

    print(Fore.MAGENTA + "General Options:")
    print(Fore.YELLOW + "  -flags <flags>       " + Fore.WHITE + "Nmap flags to use, e.g., -sS -sV -O --script vuln")
    print(Fore.RED    + "                       IMPORTANT: -flags/--flags consumes ALL remaining")
    print(Fore.RED    + "                       arguments, so it MUST be the LAST option on the")
    print(Fore.RED    + "                       command line - anything after it (including -t/-ts/-f)")
    print(Fore.RED    + "                       will be treated as an nmap flag, not a target.")
    print(Fore.YELLOW + "  -h, --help           " + Fore.WHITE + "Show this help menu")
    print(Fore.YELLOW + "  --json <file>        " + Fore.WHITE + "Save results to JSON instead of printing\n")

    print(Fore.MAGENTA + "Nmap Scan Types:")
    print(Fore.YELLOW + "  -sS                  " + Fore.WHITE + "TCP SYN scan (default stealth scan)")
    print(Fore.YELLOW + "  -sT                  " + Fore.WHITE + "TCP connect scan")
    print(Fore.YELLOW + "  -sU                  " + Fore.WHITE + "UDP scan")
    print(Fore.YELLOW + "  -sN, -sF, -sX        " + Fore.WHITE + "TCP Null, FIN, Xmas scans")
    print(Fore.YELLOW + "  -sA                  " + Fore.WHITE + "TCP ACK scan (firewall/filtered check)")
    print(Fore.YELLOW + "  -sW                  " + Fore.WHITE + "TCP Window scan")
    print(Fore.YELLOW + "  -sM                  " + Fore.WHITE + "TCP Maimon scan\n")

    print(Fore.MAGENTA + "Service & OS Detection:")
    print(Fore.YELLOW + "  -sV                  " + Fore.WHITE + "Version detection")
    print(Fore.YELLOW + "  -O                   " + Fore.WHITE + "OS detection")
    print(Fore.YELLOW + "  --osscan-guess       " + Fore.WHITE + "Guess OS more aggressively")
    print(Fore.YELLOW + "  -A                   " + Fore.WHITE + "Aggressive scan (OS, version, script, traceroute)\n")

    print(Fore.MAGENTA + "Port Specification:")
    print(Fore.YELLOW + "  -p <ports>           " + Fore.WHITE + "Specify ports or port ranges")
    print(Fore.YELLOW + "  --top-ports <num>    " + Fore.WHITE + "Scan top <num> ports")
    print(Fore.YELLOW + "  --exclude-ports <num> " + Fore.WHITE + "Exclude ports from scan")
    print(Fore.YELLOW + "  -F                   " + Fore.WHITE + "Fast scan (fewer ports)\n")

    print(Fore.MAGENTA + "Host Discovery & Timing:")
    print(Fore.YELLOW + "  -Pn                  " + Fore.WHITE + "Treat all hosts as online, skip host discovery")
    print(Fore.YELLOW + "  -n                   " + Fore.WHITE + "No DNS resolution")
    print(Fore.YELLOW + "  -R                   " + Fore.WHITE + "Always resolve DNS")
    print(Fore.YELLOW + "  -T0..T5              " + Fore.WHITE + "Timing templates (0 slowest, 5 fastest)\n")

    print(Fore.MAGENTA + "Nmap Scripts:")
    print(Fore.YELLOW + "  --script <scripts>   " + Fore.WHITE + "Run Nmap scripts, e.g., vuln, default, safe, auth\n")

    print(Fore.MAGENTA + "Output Options:")
    print(Fore.YELLOW + "  -oN <file>           " + Fore.WHITE + "Normal output to file")
    print(Fore.YELLOW + "  -oX <file>           " + Fore.WHITE + "XML output to file")
    print(Fore.YELLOW + "  -oG <file>           " + Fore.WHITE + "Grepable output")
    print(Fore.YELLOW + "  -oA <basename>       " + Fore.WHITE + "All formats with given basename\n")

    print(Fore.MAGENTA + "Other Useful Flags:")
    print(Fore.YELLOW + "  --open               " + Fore.WHITE + "Show only open ports")
    print(Fore.YELLOW + "  -v                   " + Fore.WHITE + "Increase verbosity")
    print(Fore.YELLOW + "  -d                   " + Fore.WHITE + "Increase debugging information")
    print(Fore.YELLOW + "  --reason             " + Fore.WHITE + "Display reason a port is in a particular state")
    print(Fore.YELLOW + "  --version            " + Fore.WHITE + "Show Nmap version\n")

    print(Fore.GREEN + "EXAMPLES:")
    print(Fore.CYAN + "  Snmap -f ips.txt")
    print(Fore.CYAN + "  Snmap -t 192.168.1.10 -flags -sV")
    print(Fore.CYAN + "  Snmap -ts 192.168.1.0/24 -flags -A --open\n")

# ----------- Target Validation ----------- #
# Accepts things that look like an IPv4 address, hostname, or CIDR range.
# Explicitly rejects anything starting with '-' so a malicious/malformed
# target line can never be interpreted as an extra nmap/python-nmap
# command-line option (argument injection).
_TARGET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-/]*$')


def is_valid_target(target: str) -> bool:
    """Return True if `target` is safe to hand to python-nmap as a host."""
    if not target:
        return False
    if target.startswith('-'):
        return False
    return bool(_TARGET_RE.match(target))


# ----------- Read IPs ----------- #
def read_ips(file_path):
    try:
        with open(file_path, 'r') as f:
            raw_lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)

    valid_targets = []
    for line in raw_lines:
        if is_valid_target(line):
            valid_targets.append(line)
        else:
            print(f"{Fore.RED}Warning: skipping invalid target in {file_path}: {line!r}{Style.RESET_ALL}")
    return valid_targets

# ----------- Get Targets ----------- #
def get_targets(args):
    targets = []

    if args.file:
        targets.extend(read_ips(args.file))

    if args.target:
        if is_valid_target(args.target):
            targets.append(args.target)
        else:
            print(f"{Fore.RED}Warning: ignoring invalid -t target: {args.target!r}{Style.RESET_ALL}")

    if args.subnet:
        if is_valid_target(args.subnet):
            targets.append(args.subnet)
        else:
            print(f"{Fore.RED}Warning: ignoring invalid -ts subnet: {args.subnet!r}{Style.RESET_ALL}")

    if not targets:
        print(f"{Fore.RED}No valid targets specified. Use -f, -t, or -ts{Style.RESET_ALL}")
        sys.exit(1)

    return targets

# ----------- Run Nmap Scan ----------- #
def run_nmap_scan(ip, flags):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=" ".join(flags))
        return nm[ip] if ip in nm.all_hosts() else None
    except nmap.PortScannerError as e:
        print(f"{Fore.RED}[nmap error] Target {ip} failed - nmap itself reported an error: {e}{Style.RESET_ALL}")
        return None
    except KeyError as e:
        print(f"{Fore.RED}[parse error] Target {ip} failed - unexpected/missing field in scan result: {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[error] Target {ip} failed - {type(e).__name__}: {e}{Style.RESET_ALL}")
        return None

# ----------- Format Results ----------- #
def format_results(results):
    formatted = {}
    for ip, scan in results.items():
        if not scan:
            formatted[ip] = {"error": "No results or host down"}
            continue

        ip_data = {}


        os_guesses = []
        if 'osmatch' in scan:
            for osmatch in scan['osmatch']:
                guess = f"{osmatch['name']} ({osmatch['accuracy']}%)"
                if guess not in os_guesses:
                    os_guesses.append(guess)
        if os_guesses:
            ip_data["OS"] = os_guesses

        # פורטים
        ports_info = []
        for proto in scan.all_protocols():
            for port in sorted(scan[proto].keys()):
                port_data = {
                    "protocol": proto,
                    "port": port,
                    "state": scan[proto][port]['state'],
                    "service": scan[proto][port].get('name', ''),
                    "product": scan[proto][port].get('product', ''),
                    "version": scan[proto][port].get('version', ''),
                    "reason": scan[proto][port].get('reason', '')
                }
                if port_data not in ports_info:
                    ports_info.append(port_data)
        if ports_info:
            ip_data["ports"] = ports_info


        scripts = {}
        for proto in scan.all_protocols():
            for port in scan[proto].keys():
                if 'script' in scan[proto][port]:
                    for script_name, output in scan[proto][port]['script'].items():
                        scripts.setdefault(port, {})[script_name] = output
        if scripts:
            ip_data["scripts"] = scripts

        formatted[ip] = ip_data
    return formatted

# ----------- Display Results ----------- #
def display_results(formatted):
    print(f"{Fore.MAGENTA}\n=== Scan Results ==={Style.RESET_ALL}\n")
    for ip, data in formatted.items():
        print(f"{Fore.CYAN}Host: {ip}{Style.RESET_ALL}")
        if "error" in data:
            print(f"  {Fore.RED}{data['error']}{Style.RESET_ALL}\n")
            continue

        if "OS" in data:
            print(f"{Fore.YELLOW}  [ Operating System Guesses ]{Style.RESET_ALL}")
            for os in data["OS"]:
                print(f"    {Fore.GREEN}{os}{Style.RESET_ALL}")

        if "ports" in data:
            print(f"{Fore.YELLOW}  [ Ports ]{Style.RESET_ALL}")
            for p in data["ports"]:
                state_color = {
                    "open": Fore.GREEN,
                    "filtered": Fore.YELLOW,
                    "closed": Fore.RED
                }.get(p["state"], Fore.WHITE)

                svc_info = f"{p['service']} {p['product']} {p['version']}".strip()
                reason_info = f" | Reason: {p['reason']}" if p['reason'] else ""
                print(f"    Port {p['port']}/{p['protocol']}: {state_color}{p['state']}{Style.RESET_ALL} | {svc_info}{reason_info}")

        if "scripts" in data:
            print(f"{Fore.YELLOW}  [ Scripts ]{Style.RESET_ALL}")
            for port, scripts in data["scripts"].items():
                for script_name, output in scripts.items():
                    print(f"    {Fore.BLUE}{port} - {script_name}:{Style.RESET_ALL} {output}")
        print("")

# ----------- Ordering Safety Check ----------- #
def check_flags_ordering(argv):
    """
    -flags/--flags uses argparse.REMAINDER, which swallows every argument
    that comes after it - including -t/-ts/-f. If a user puts -flags before
    a target option, that target option is silently absorbed into the nmap
    flags instead of being parsed as a target. Warn loudly if we detect that.
    """
    flag_tokens = ("-flags", "--flags")
    target_tokens = ("-f", "--file", "-t", "--target", "-ts", "--subnet")

    flag_index = None
    for i, token in enumerate(argv):
        if token in flag_tokens:
            flag_index = i
            break

    if flag_index is None:
        return

    for token in argv[flag_index + 1:]:
        if token in target_tokens:
            print(f"{Fore.RED}Warning: '{token}' appears AFTER -flags/--flags on the command line.{Style.RESET_ALL}")
            print(f"{Fore.RED}-flags/--flags consumes ALL remaining arguments, so '{token}' will be passed "
                  f"to nmap as a flag instead of being parsed as a target option.{Style.RESET_ALL}")
            print(f"{Fore.RED}Fix: put -flags/--flags LAST on the command line, e.g. "
                  f"'Snmap -t 192.168.1.10 -flags -sV'{Style.RESET_ALL}\n")
            break

# ----------- Main ----------- #
def main():
    print_logo()

    check_flags_ordering(sys.argv[1:])

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", "--file", help="File containing IP addresses")
    parser.add_argument("-t", "--target", help="Single IP address to scan")
    parser.add_argument("-ts", "--subnet", help="Subnet to scan in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("-flags", "--flags", nargs=argparse.REMAINDER, default=["-sS"],
                         help="Nmap flags to use, e.g. -sS -sV -O --script vuln. "
                              "MUST be the last option on the command line - everything "
                              "after -flags/--flags is passed straight through to nmap.")
    parser.add_argument("--json", help="Save results to JSON instead of printing")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    args = parser.parse_args()

    if len(sys.argv) == 1 or args.help:
        help_menu()
        sys.exit(0)

    targets = get_targets(args)
    results = {}

    print(f"{Fore.MAGENTA}Starting Nmap scan on {len(targets)} targets with flags: {' '.join(args.flags)}{Style.RESET_ALL}\n")

    for ip in tqdm(targets, desc="Scanning Targets", unit="host"):
        scan_result = run_nmap_scan(ip, args.flags)
        results[ip] = scan_result
        time.sleep(0.1)

    print(f"\n{Fore.MAGENTA}Scan completed! Processing results...{Style.RESET_ALL}\n")
    formatted = format_results(results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(formatted, f, indent=4)
        print(f"{Fore.GREEN}Results saved to {args.json}{Style.RESET_ALL}")
    else:
        display_results(formatted)

if __name__ == "__main__":
    main()
