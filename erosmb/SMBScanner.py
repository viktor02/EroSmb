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
            logging.error('%s: %s' % (self.target_ip, str(e)))

    def get_info(self):
        dialect = self.conn.getDialect()
        server_domain = self.conn.getServerDomain()
        server_name = self.conn.getServerName()
        server_os = self.conn.getServerOS()
        server_os_major = self.conn.getServerOSMajor()
        dns_hostname = self.conn.getServerDNSHostName()
        remote_host = self.conn.getRemoteHost()
        is_login_required = self.conn.isLoginRequired()
        credentials = self.conn.getCredentials()
        server_arch = self.get_arch()

        return dialect, server_domain, server_name, server_os, server_os_major, server_arch, dns_hostname, \
               remote_host, is_login_required, credentials

    def scan(self) -> dict:
        for port in self.ports:
            logging.info(f"Trying port {port} @ {self.target_ip}")
            if self.connect(port):
                self.login()
                dialect, server_domain, server_name, server_os, server_os_major, server_arch, dns_hostname, \
                remote_host, is_login_required, credentials = self.get_info()


                if "2600" in server_os: server_os += " (Windows XP)"
                if "3790" in server_os: server_os += " (Windows XP Professional x64 Edition)"
                if "2715" in server_os: server_os += " (Windows XP Media Center Edition 2006)"
                if "6002" in server_os: server_os += " (Windows Vista)"
                if "7601" in server_os: server_os += " (Windows 7)"
                if "9200" in server_os: server_os += " (Windows 8)"
                if "9600" in server_os: server_os += " (Windows 8.1)"
                if "10240" in server_os: server_os += " (Windows 10 NT10.0)"
                if "10586" in server_os: server_os += " (Windows 10 1511)"
                if "14393" in server_os: server_os += " (Windows 10 1607)"
                if "15063" in server_os: server_os += " (Windows 10 1703)"
                if "16299" in server_os: server_os += " (Windows 10 1709)"
                if "16299" in server_os: server_os += " (Windows 10 1709)"
                if "17134" in server_os: server_os += " (Windows 10 1803)"
                if "18362" in server_os: server_os += " (Windows 10 1903)"
                if "18363" in server_os: server_os += " (Windows 10 1909)"
                if "19041" in server_os: server_os += " (Windows 10 2004)"
                if "19042" in server_os: server_os += " (Windows 10 20H2)"
                if "19043" in server_os: server_os += " (Windows 10 21H1)"
                if "19044" in server_os: server_os += " (Windows 10 21H2)"
                if "22000" in server_os: server_os += " (Windows 11 21H2)"

                return {
                    "host": remote_host,
                    "os": server_os,
                    "arch": server_arch,
                    "domain": server_domain,
                    "name": server_name,
                    "dns_hostname": dns_hostname,
                    "is_login_required": is_login_required
                }
        return {}
