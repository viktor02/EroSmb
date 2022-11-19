import argparse
import logging
import ipaddress
import threading

from erosmb.Machine import Machine
from erosmb.SMBScanner import SMBScanner
from colorama import init, Fore, Style

__version__ = "0.1.4"

parser = argparse.ArgumentParser(description='Enumerate Windows machines in network.')

parser.add_argument("target", help="target IPs. May be range 192.168.0.0/24 or single ip")
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="print warnings")
parser.add_argument("-vv", "-d", "--debug", default=False, action="store_true", help="print debug information")
parser.add_argument("-t", "--timeout", default=0.1, type=float, help="timeout before deciding to mark a port as closed")
parser.add_argument("-o", "--output", default=False, type=str, help="file to output list of machines")
parser.add_argument("-s", "--sort", default=False, action="store_true", help="sort by kernel version")
parser.add_argument('-V', '--version', action='version', version=__version__)
parser.add_argument("--username", default="anonymous")
parser.add_argument("--password", default="anonymous", help="password for username")
parser.add_argument("--domain", default="LANPARTY", help="domain for username")
parser.add_argument("--nologo", default=False, action="store_true", help="do not display logo")
parser.add_argument("--nothreads", default=False, action="store_true", help="do not use multithreading")

args = parser.parse_args()

if args.debug:
    logging.root.setLevel(logging.INFO)
elif args.verbose:
    logging.root.setLevel(logging.WARNING)
else:
    logging.root.setLevel(logging.ERROR)

log = logging.getLogger(__name__)
formatter = logging.Formatter('%(levelname)s | %(name)s | %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)


def banner():
    print(f"{Fore.MAGENTA}EroSmb {__version__} | enumerate Windows machines in your network{Style.RESET_ALL}\n")


machines = []


def common_scan(ip):
    smb_scanner = SMBScanner(ip)
    machine = smb_scanner.scan(args.username, args.password, args.domain)

    if machine is not None:
        # output immediately, if we don't need sorting
        if not args.sort:
            print_info(machine)

        machines.append(machine)


def print_info(machine: Machine):
    answer = f"{Fore.GREEN}[{machine.ip:^15}]{Fore.RESET} " \
             f"{machine.os:<45} {Fore.YELLOW}{machine.arch}{Fore.RESET} " \
             f"[{Fore.CYAN}{machine.domain}\\\\{machine.name}{Fore.RESET}]"

    if machine.logged_in:
        answer += f" {Fore.RED}Logged in as {args.username}{Fore.RESET}"

    if args.verbose or args.debug:
        print(answer,
              Fore.GREEN, "DNS:", machine.dns_name, "IsLoginReq:", machine.is_login_req,
              "SMBVer:", hex(machine.smb_dialect),
              Fore.RESET)
    else:
        print(answer)


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

    if args.verbose:
        print(f"Current online: {Fore.GREEN}{len(machines)}{Fore.RESET}")

    if args.sort:
        sorted_machines = list(machines)
        sorted_machines.sort(key=lambda machine: machine.os, reverse=True)
        for machine in sorted_machines:
            print_info(machine)

    if args.output:
        try:
            f = open(args.output, "w", encoding='utf8')
            for machine in machines:
                f.write(machine.ip + "\n")
            print("Written to file", f.name)
            f.close()
        except FileNotFoundError:
            log.error("Error writing to file: bad filename")
        except PermissionError:
            log.error("Error writing to file: not enough permissions.")
        except Exception as e:
            log.error(e)


if __name__ == "__main__":
    main()
