import logging
import socket
from multiprocessing import Process

from colorama import Fore


class PortScanner:
    def __init__(self, ip, timeout=0.1):
        self.ip = ip
        self.ports = (21, 22, 80, 139, 443, 445, 3389, 8080)
        self.timeout = timeout

    def scan(self) -> list:
        open_ports = list()
        try:
            for port in self.ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.ip, port))
                if result == 0:
                    logging.info(f"Port {port} @ {self.ip} is open")
                    open_ports.append(port)
                sock.close()
            print(f"{Fore.GREEN}[{self.ip}]{Fore.RESET} Open ports: {Fore.LIGHTBLUE_EX}{open_ports}{Fore.RESET}")

        except KeyboardInterrupt:
            logging.warning("Stopping by user")
        except socket.error as e:
            logging.error(e)
        return open_ports

    def run_pool(self, workers=10):
        for i in range(workers):
            Process(target=self.scan).start()
