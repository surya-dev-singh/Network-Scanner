import scapy.all as scapy
from termcolor import colored
import argparse
import time
import requests
import ipaddress
def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target", help="target IP or CIDER notation")
    options=parser.parse_args()
    if options.target:
        return options
    else:
        parser.error(colored("please specify the target or use -h or --help to learn more !!","red"))
        exit()
def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_brodcast=brodcast/arp_request
    ans=scapy.srp(arp_request_brodcast,timeout=15,verbose=False)[0] 
    client_list=[]
    for i in ans:
        # i[1].show()
        client_dict={"ip":i[1].psrc,"mac":i[1].hwsrc}
        client_list.append(client_dict)
    return client_list
def print_result(results_list):
    url="https://api.macvendors.com/"
    for client in results_list:
        time.sleep(1)
        response = requests.get(url+client["mac"])
        if response.status_code != 200:
            vendor=colored("Mac Address randomization used!!","red")
        else:
            vendor = response.content.decode("utf-8")
        print(client["ip"],"\t\t\t",client["mac"],"\t\t\t",vendor)

options=get_arguments()
print()
print(colored("[+] scanning network ....","green"))
print()
print(colored("=====================================================================================================\nIP_ADDRESS\t\t\t    MAC_ADDRESS\t\t\t\t    VENDOR\n=====================================================================================================\n","green"))
scan_result=scan(str(options.target))
print_result(scan_result)
print()
