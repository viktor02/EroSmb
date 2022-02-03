import logging

import impacket.smb3structs
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
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
            logging.info(e)
            return False

    def login(self, login="anonymous", password="anonymous", domain='LANPARTY', lmhash='', nthash=''):
        try:
            self.conn.negotiateSession()
            self.conn.login(login, password, domain, lmhash, nthash)
        except impacket.smbconnection.SessionError as e:
            logging.warning(e)

    def get_arch(self):
        try:
            string_binding = r'ncacn_ip_tcp:%s[135]' % self.target_ip
            transport = DCERPCTransportFactory(string_binding)
            transport.set_connect_timeout(int(1))
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except DCERPCException as e:
                if str(e).find('syntaxes_not_supported') >= 0:
                    return "32-bit"
                else:
                    logging.error(str(e))
                    pass
            else:
                return "64-bit"

            dce.disconnect()
        except Exception as e:
            # import traceback
            # traceback.print_exc()
            logging.error('%s: %s' % (self.target_ip, str(e)))

    def get_info(self):
        dialect = self.conn.getDialect()
        server_domain = self.conn.getServerDomain()
        server_name = self.conn.getServerName()
        server_os = self.conn.getServerOS()
        dns_hostname = self.conn.getServerDNSHostName()
        remote_host = self.conn.getRemoteHost()
        arch = self.get_arch()

        return dialect, server_domain, server_name, server_os, arch, dns_hostname, remote_host

    def scan(self) -> list:
        targets_info = list()
        for port in self.ports:
            logging.info(f"Trying port {port} @ {self.target_ip}")
            if self.connect(port):
                self.login()
                dialect, server_domain, server_name, server_os, server_arch, dns_hostname, remote_host = self.get_info()
                target = {
                    "dialect": dialect,
                    "server_domain": server_domain,
                    "server_name": server_name,
                    "server_os": server_os,
                    "server_arch": server_arch,
                    "dns_hostname": dns_hostname,
                    "remote_host": remote_host
                }
                targets_info.append(target)
                print(f"[{remote_host}] {server_os} {server_arch} [{server_domain}\\\\{server_name}]")
        return targets_info
