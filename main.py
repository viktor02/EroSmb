import argparse
import logging
import ipaddress
import threading

import SMBScanner
from PortScanner import PortScanner

parser = argparse.ArgumentParser(description='Enumerate Windows machines in network.')
parser.add_argument("target", help="Target IPs. May be range 192.168.0.0/24 or single ip")
parser.add_argument("-d", "--debug", default=False, action="store_true", help="Print debug information")

parser.add_argument("--nothreads", help="Run in single process")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(encoding='utf-8', level=logging.DEBUG)
else:
    logging.basicConfig(encoding='utf-8', level=logging.WARNING, format="%(asctime)s %(message)s")


def banner():
    logo = open("logo.txt").read()
    logo += "\n\nSmb and Port scanner\n"
    print(logo)


def common_scan(ip):
    smb_scanner = SMBScanner.SMBScanner(ip)
    smb_info = smb_scanner.scan()

    port_scanner = PortScanner(ip)
    ports = port_scanner.scan()


def main():
    banner()
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
