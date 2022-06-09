#By mr_maroga

import socket
from IPy import IP


class PortScan():
    banners = []
    open_port = []

    def __init__(self, target, port_num):
        self.target = target
        self.port_num = port_num

    def scan(self):
        for port in self.port_num:
            self.is_port_open(port)

    def check_ip(self):
        try:
            IP(self.target)
            return self.target
        except ValueError:
            return socket.gethostbyname(self.target)

    def is_port_open(self, port):

        try:
            converted_ip = self.check_ip()
            # try to connect to host using that port
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((converted_ip, port))
            self.open_ports.append(port)
            # the connection was established, port is Available for attack
            try:
                banner = sock.revc(1024).decode().strip('\n'.strip("\r"))
                self.banner.append(banner)

            except:
                self.banners.append(' ')

                if port == 20 or port == 21:
                    print(f"[+] FTp port {port} attack")
                if port == 23:
                    print(f"[+] Telnet {port} attack")
                if port == 80 or port == 8080:
                    print(f"[+] Http port {port} attack")
                if port == 43:
                    print(f"[+] Https port {port} attack")
                if port == 161:
                    print(f"[+] Smtp port {port} attack")
                if port == 110:
                    print(f"[+] POP3 port {port} attack")
                if port == 143:
                    print(f"[+] IMAP port {port} attack")
                if port == 137 or port == 138 or port == 139:
                    print(f"[+] BIOS port {port} attack")
                if port == 22:
                    print(f"[+] SSH port {port} attack")
                if port == 68:
                    print(f"[+] DHCP client port {port} attack")
                if port == 67:
                    print(f"[+] DHCP server port {port} attack")
                if port == 53:
                    print(f"[+] DNS port {port} attack")
                if port == 69:
                    print(f"[+] TFTP port {port} attack")
                if port == 70:
                    print(f"[+] Gopher port {port} attack")
                if port == 79:
                    print(f"[+] Finger port {port} attack")
                if port == 161:
                    print(f"[+] SNMP port {port} attack")
                if port == 179:
                    print(f"[+] BGP port {port} attack")
                if port == 389:
                    print(f"[+] LDAP port {port} attack")
                if port == 5800 or port == 5900:
                    print(f"[+] VNC port {port} attack")

            sock.close()
        except:
            # cannot connect, port is closed
            # Not import
            # print(f"[-] port {port} is closed")
            pass
