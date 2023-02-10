import ipaddress


class Machine:
    ip: ipaddress.IPv4Address
    os: str
    arch: str
    domain: str
    name: str
    dns_name: str
    is_login_req: bool
    logged_in: bool
    smb_dialect: int

    def __init__(self, ip):
        self.ip = ip
        self.os = ""
        self.arch = ""
        self.domain = ""
        self.name = ""
        self.dns_name = ""
        self.is_login_req = False
        self.logged_in = False
        self.smb_dialect = 0x0
