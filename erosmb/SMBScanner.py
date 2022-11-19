import logging

import impacket.smb3structs
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.smbconnection import SMBConnection
from erosmb.Machine import Machine


class SMBScanner:
    def __init__(self, target_ip):
        self.conn = None
        self.target_ip = target_ip
        self.ports = [139, 445]
        self.logger = logging.getLogger(__name__)

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
        machine = Machine(self.target_ip)

        machine.smb_dialect = self.conn.getDialect()
        machine.domain = self.conn.getServerDomain()
        machine.name = self.conn.getServerName()
        machine.os = self.conn.getServerOS()
        machine.dns_name = self.conn.getServerDNSHostName()
        machine.is_login_req = self.conn.isLoginRequired()
        machine.arch = self.get_arch()

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
            if osv in machine.os:
                machine.os = "{} ({})".format(os_versions[osv], machine.os)

        return machine

    def scan(self, username, password, domain) -> Machine | None:
        for port in self.ports:
            self.logger.info(f"Trying port {port} @ {self.target_ip}")
            if self.connect(port):
                self.logger.info(f"Connected to {self.target_ip}:{port}")
                logged_in = self.login(username, password, domain)
                machine = self.get_info()
                machine.logged_in = logged_in
                return machine
        return None
