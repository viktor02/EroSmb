import argparse
import logging
import ipaddress
import threading

import SMBScanner
from PortScanner import PortScanner
from colorama import init, Fore, Style

parser = argparse.ArgumentParser(description='Enumerate Windows machines in network.')
parser.add_argument("target", help="Target IPs. May be range 192.168.0.0/24 or single ip")
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Print warnings")
parser.add_argument("-d", "-vv", "--debug", default=False, action="store_true", help="Print debug information")
parser.add_argument("-sP", "--portscan", default=False, action="store_true", help="Scan popular ports")
parser.add_argument("-t", "--timeout", default=0.1, type=float, help="Timeout before deciding to mark a port as closed")
parser.add_argument("--nothreads", default=False, action="store_true", help="Do not use multithreading")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(encoding='utf-8', level=logging.DEBUG)
if args.verbose:
    logging.basicConfig(encoding='utf-8', level=logging.WARNING, format="%(asctime)s %(message)s")
else:
    logging.basicConfig(encoding='utf-8', level=logging.ERROR, format="%(asctime)s %(message)s")


def banner():
    logo = open("logo.txt").read()
    logo += "\n\nSmb and Port scanner\n"
    print(logo)


def common_scan(ip):
    smb_scanner = SMBScanner.SMBScanner(ip)
    smb_info = smb_scanner.scan()

    if args.portscan:
        port_scanner = PortScanner(ip, args.timeout)
        ports = port_scanner.scan()


def main():
    init()
    print(Fore.MAGENTA)
    banner()
    print(Style.RESET_ALL)
    threads = []
    for ip in ipaddress.IPv4Network(args.target):
        if args.nothreads:
            common_scan(ip.compressed)
        else:
            thread = threading.Thread(target=common_scan, args=(ip.compressed,))

            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
