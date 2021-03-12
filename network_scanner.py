import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    args = parser.parse_args()
    if args.target == "":
        print('argument missing')
        exit()

    return args


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for item in answered_list:
        client_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def get_mac_by_ip(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc



def format_result(results_list):
    print("IP\t\t\tMAC Adress")
    print("----------------------------------")
    for client in results_list:
        print(client['ip'] + "\t\t\t" + client['mac'])


#options = get_arguments()
#scan_result = scan(options.target)
#format_result(scan_result)
