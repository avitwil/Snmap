#!/usr/bin/env python3
import argparse
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
    print(Fore.CYAN + "================= Presents to you =================\n")
    print(Fore.RED + pyfiglet.figlet_format(" Super Nmap ", font="slant"))
    print(Fore.GREEN + "================= Avi Twil (c) =================\n")

# ----------- Help Menu ----------- #
def help_menu():
    print(Fore.YELLOW + "USAGE: " + Fore.CYAN +
          "Snmap -f <ip_file> [-flags <NMAP_FLAGS>]\n")

    print(Fore.MAGENTA + "Options:")
    print(Fore.YELLOW + "  -f <file>            " + Fore.WHITE + "File containing list of IPs")
    print(Fore.YELLOW + "  -flags <flags>       " + Fore.WHITE + "Nmap flags to use, e.g., -sS -sV -O --script vuln")
    print(Fore.YELLOW + "  -h, --help           " + Fore.WHITE + "Show this help menu\n")

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
    print(Fore.CYAN + "  Snmap -f ips.txt -flags -sS -sV --script vuln")
    print(Fore.CYAN + "  Snmap -f ips.txt -flags -A -p 22,80,443 --open\n")

# ----------- Read IPs ----------- #
def read_ips(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)

# ----------- Run Nmap Scan ----------- #
def run_nmap_scan(ip, flags):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=" ".join(flags))
        return nm[ip] if ip in nm.all_hosts() else None
    except Exception as e:
        print(f"{Fore.RED}Error scanning {ip}: {e}{Style.RESET_ALL}")
        return None

# ----------- Display Results ----------- #
def display_results(results):
    print(f"{Fore.MAGENTA}\n=== Scan Results ==={Style.RESET_ALL}\n")
    for ip, scan in results.items():
        print(f"{Fore.CYAN}Host: {ip}{Style.RESET_ALL}")
        if not scan:
            print(f"  {Fore.RED}No results or host down.{Style.RESET_ALL}\n")
            continue


        if 'osmatch' in scan:
            for osmatch in scan['osmatch']:
                print(f"  {Fore.GREEN}OS Guess: {osmatch['name']} ({osmatch['accuracy']}%){Style.RESET_ALL}")


        for proto in scan.all_protocols():
            print(f"  Protocol: {proto}")
            ports = scan[proto].keys()
            for port in sorted(ports):
                state = scan[proto][port]['state']
                service_name = scan[proto][port].get('name', '')
                product = scan[proto][port].get('product', '')
                version = scan[proto][port].get('version', '')
                reason = scan[proto][port].get('reason', '')

                # צבע לפי סטטוס
                if state == "open":
                    color = Fore.GREEN
                elif state == "filtered":
                    color = Fore.YELLOW
                elif state == "closed":
                    color = Fore.RED
                else:
                    color = Fore.WHITE

                svc_info = f"{service_name} {product} {version}".strip()
                reason_info = f" | Reason: {reason}" if reason else ""
                print(f"    Port {port}: {color}{state}{Style.RESET_ALL} | Service: {svc_info}{reason_info}")


                if 'script' in scan[proto][port]:
                    for script_name, output in scan[proto][port]['script'].items():
                        print(f"      {Fore.BLUE}{script_name}: {output}{Style.RESET_ALL}")
        print("")

# ----------- Main ----------- #
def main():
    print_logo()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", "--file", help="File containing IP addresses")
    parser.add_argument("-flags", "--flags", nargs=argparse.REMAINDER, default=["-sS"], help="Nmap flags to use")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    args = parser.parse_args()

    if len(sys.argv) == 1 or args.help:
        help_menu()
        sys.exit(0)

    if not args.file:
        print(f"{Fore.RED}No IP file specified. Please use -f <file> or run with -h for help.{Style.RESET_ALL}")
        sys.exit(1)

    ips = read_ips(args.file)
    results = {}

    print(f"{Fore.MAGENTA}Starting Nmap scan on {len(ips)} hosts with flags: {' '.join(args.flags)}{Style.RESET_ALL}\n")

    for ip in tqdm(ips, desc="Scanning IPs", unit="host"):
        scan_result = run_nmap_scan(ip, args.flags)
        results[ip] = scan_result
        time.sleep(0.1)

    print(f"\n{Fore.MAGENTA}Scan completed! Displaying results:{Style.RESET_ALL}\n")
    display_results(results)

if __name__ == "__main__":
    main()