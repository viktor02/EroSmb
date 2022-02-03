import logging
import socket

import impacket.smb3structs
from impacket.smbconnection import SMBConnection


class SMBScanner:
    def __init__(self, target_ip):
        self.conn = None
        self.target_ip = target_ip
        self.ports = [139, 445]

    def connect(self, port) -> bool:
        try:
            self.conn = SMBConnection(remoteName=self.target_ip, remoteHost=self.target_ip, myName=None,
                                      sess_port=port,
                                      timeout=4, preferredDialect=None)
            return True
        except Exception as e:
            logging.error(e)
            return False

    def login(self, login="anonymous", password="anonymous", domain='LANPARTY', lmhash='', nthash=''):
        try:
            self.conn.negotiateSession()
            self.conn.login(login, password, domain, lmhash, nthash)
        except impacket.smbconnection.SessionError as e:
            logging.warning(e)

    def get_info(self):
        dialect = self.conn.getDialect()
        server_domain = self.conn.getServerDomain()
        server_name = self.conn.getServerName()
        server_os = self.conn.getServerOS()
        dns_hostname = self.conn.getServerDNSHostName()
        remote_host = self.conn.getRemoteHost()

        return dialect, server_domain, server_name, server_os, dns_hostname, remote_host

    def scan(self) -> list:
        targets_info = list()
        for port in self.ports:
            logging.info(f"Trying port {port} @ {self.target_ip}")
            if self.connect(port):
                self.login()
                dialect, server_domain, server_name, server_os, dns_hostname, remote_host = self.get_info()
                target = {
                    "dialect": dialect,
                    "server_domain": server_domain,
                    "server_name": server_name,
                    "server_os": server_os,
                    "dns_hostname": dns_hostname,
                    "remote_host": remote_host
                }
                targets_info.append(target)
                print(f"{remote_host} - {server_os} @ {server_domain}\\\\{server_name}")
        return targets_info
