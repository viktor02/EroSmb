import argparse
import logging
import ipaddress
import threading

from erosmb.SMBScanner import SMBScanner
from erosmb.PortScanner import PortScanner
from colorama import init, Fore, Style

parser = argparse.ArgumentParser(description='Enumerate Windows machines in network.')
parser.add_argument("target", help="Target IPs. May be range 192.168.0.0/24 or single ip")
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Print warnings")
parser.add_argument("-vv", "-d", "--debug", default=False, action="store_true", help="Print debug information")
parser.add_argument("-sP", "--portscan", default=False, action="store_true", help="Scan popular ports")
parser.add_argument("-t", "--timeout", default=0.1, type=float, help="Timeout before deciding to mark a port as closed")
parser.add_argument("--nothreads", default=False, action="store_true", help="Do not use multithreading")
parser.add_argument("-o", "--output", default=False, type=str, help="File to output list of machines")
parser.add_argument("--nologo", default=False, action="store_true", help="Do not display logo")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(encoding='utf-8', level=logging.DEBUG)
if args.verbose:
    logging.basicConfig(encoding='utf-8', level=logging.WARNING, format="%(asctime)s %(message)s")
else:
    logging.basicConfig(encoding='utf-8', level=logging.ERROR, format="%(asctime)s %(message)s")


def banner():
    logo = """\
eeeeee            ssssssss
ee                ss                b
eeeeee rrrr  ooo  ssssssss  mm  mm  bbbb
ee     rr   o   o       ss  m mm m  b  bb
eeeeee r     ooo  ssssssss  m    m  bbbb
________________________________________
"""
    logo += "\n\nSmb and Port scanner\n"
    print(Fore.MAGENTA)
    print(logo)
    print(Style.RESET_ALL)


machines = []


def common_scan(ip):
    smb_scanner = SMBScanner(ip)
    smb_info = smb_scanner.scan()

    if len(smb_info) > 0:
        machines.append(smb_info)

    if args.portscan:
        port_scanner = PortScanner(ip, args.timeout)
        ports = port_scanner.scan()


def main():
    init()

    if not args.nologo:
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

    logging.info(f"Current online: {Fore.GREEN}{len(machines)}{Fore.RESET}")

    if args.output:
        try:
            f = open(args.output, "w", encoding='utf8')
            for machine in machines:
                f.write(machine[0] + "\n")
            print("Written to file", f.name)
            f.close()
        except FileNotFoundError:
            logging.error("Error writing to file: bad filename")


if __name__ == "__main__":
    main()
