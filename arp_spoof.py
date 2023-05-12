import subprocess
import optparse
import re

#parse the args user returns return interface & mac
def arg_parser():
    parser = optparse.OptionParser() 
    parser.add_option("-i", "--interface", dest="interface", help="Interface whose MAC to change" )
    parser.add_option("-m", "--mac", dest="mac_address", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        print("[-] Please specify interface, use --help for more info")
    elif not options.mac_address:
        print("[-] Please specify mac_address, use --help for more info") 
    return options

#get the current mac address
def get_mac(interface):
     ifconfig_result = subprocess.check_output(["ifconfig", interface])
     mac_address_search = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', str(ifconfig_result))
     if mac_address_search:
         return mac_address_search.group(0)
     else:
         print("[-] Could not read MAC address")
         
    
     
#change current mac of specified interface
def mac_change(interface, mac_address):
    #user message
    print(f"[+] Changing MAC Address for {interface} to {mac_address}")
    #change MAC of interface
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",mac_address])
    subprocess.call(["ifconfig",interface,"up"])
    
def check_mac_change(current_mac, new_mac):
    if current_mac == new_mac:
        print("[+] MAC address successfully changed.")
    else:
        print("[-] Failed to change MAC address")
        

if __name__ == '__main__':
   
    #call function 
    options = arg_parser()
    mac_change(options.interface, options.mac_address)
    current_mac = get_mac(options.interface)
    check_mac_change(current_mac, options.mac_address)
   