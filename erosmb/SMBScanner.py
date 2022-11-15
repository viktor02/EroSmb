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
        self.logger = logging.getLogger('erosmb.SMB')
        self.logger.propagate = False

    def connect(self, port) -> bool:
        try:
            self.conn = SMBConnection(remoteName=self.target_ip, remoteHost=self.target_ip, myName=None,
                                      sess_port=port,
                                      timeout=4, preferredDialect=None)
            return True
        except Exception as e:
            self.logger.info(e)
            return False

    def login(self, login="anonymous", password="anonymous", domain='LANPARTY', lmhash='', nthash=''):
        logged_in = False
        try:
            self.conn.negotiateSession()
            logged_in = self.conn.login(login, password, domain, lmhash, nthash)
        except impacket.smbconnection.SessionError as e:
            self.logger.warning(e)
        return logged_in

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
                    self.logger.error(str(e))
                    pass
            else:
                return "64-bit"

            dce.disconnect()
        except Exception as e:
            self.logger.error('%s: %s' % (self.target_ip, str(e)))

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

    def scan(self, username, password, domain) -> dict:
        for port in self.ports:
            self.logger.info(f"Trying port {port} @ {self.target_ip}")
            if self.connect(port):
                logged_in = self.login(username, password, domain)

                dialect, server_domain, server_name, server_os, server_os_major, server_arch, dns_hostname, \
                remote_host, is_login_required, credentials = self.get_info()

                os_versions = {"2600": "Windows XP",
                               "3790": "Windows XP Professional x64 Edition",
                               "2715": "Windows XP Media Center Edition 2006",
                               "6002": "Windows Vista",
                               "7601": "Windows 7",
                               "9200": "Windows 8",
                               "9600": "Windows 8.1",
                               "10240": "Windows 10 NT10.0",
                               "10586": "Windows 10 1511",
                               "15063": "Windows 10 1703",
                               "16299": "Windows 10 1709",
                               "17134": "Windows 10 1803",
                               "18362": "Windows 10 1903",
                               "18363": "Windows 10 1909",
                               "19041": "Windows 10 2004",
                               "19042": "Windows 10 20H2",
                               "19043": "Windows 10 21H1",
                               "19044": "Windows 10 21H2",
                               "22000": "Windows 11 21H2"}

                for osv in os_versions.keys():
                    if osv in server_os:
                        server_os = "{} ({})".format(os_versions[osv], server_os)

                return {
                    "host": remote_host,
                    "os": server_os,
                    "arch": server_arch,
                    "domain": server_domain,
                    "name": server_name,
                    "dns_hostname": dns_hostname,
                    "is_login_required": is_login_required,
                    "logged_in": logged_in
                }
        return {}
