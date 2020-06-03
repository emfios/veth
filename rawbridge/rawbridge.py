import argparse
import threading
import socket
import struct
from scapy.all import *

sender_mcast_address    = '224.0.0.1'
receiver_mcast_address  = '224.0.0.1'
sender_port             = 9000
receiver_port           = 8000
veth_mac_address        = "60:36:DD:98:B6:53"

def raw_receiver(sock, iface, udp_dst):
    print("raw_receiver")
    print(iface)

    def sniff_callback(pkt):
        #print(pkt.sprintf("Rx>SRC:%Ether.src% DST:%Ether.dst% Type: %Ether.type%"))
        if (not pkt.haslayer(Ether)):
            print("not a Ether packet")
            return
        dst = pkt[Ether].dst
        dst = dst.upper()
        if (dst == veth_mac_address or dst == "FF:FF:FF:FF:FF:FF"):
            #print(pkt.sprintf("Rx>SRC:%Ether.src% DST:%dst% Type: %Ether.type%"))
            sock.sendto(bytes(pkt),udp_dst)
        
    sniff(prn=sniff_callback, store=0, iface=iface)
    
def raw_transmitter(sock,iface):
    print("raw_transmitter")
    print(iface)
    # read from udp and send it to scapy
    while True:
        data,addr = sock.recvfrom(65535)
	#print(len(data))
        if data:
            pkt = Ether(data)
            #print(pkt.sprintf("Tx>SRC:%Ether.src% DST:%Ether.dst% Type: %Ether.type%"))
            sendp(pkt,iface=iface, verbose=False);
    sock.close()

def display_iface():
    print(" Interface List:")
    list = get_windows_if_list()
    for l in list:
        print((l['name'] + " [" + l['description']) + "]")
        #print(l['ips'])
        port
if __name__ == "__main__":
    # Parse the command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', '-i', required=True)
    parser.add_argument('--iface_ipaddr', '-l', required=True)
    args = parser.parse_args()
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # UDP recv configuration (receiver_mcast_address, receiver_port)
    bind_addr = '0.0.0.0'
    membership = socket.inet_aton(receiver_mcast_address) + socket.inet_aton(bind_addr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, receiver_port))
    
    # UDP sender configuration
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface_ipaddr))

    raw_rx_thread = threading.Thread(target=raw_receiver,args=(sock,args.iface,(sender_mcast_address, sender_port)))
    raw_tx_thread = threading.Thread(target=raw_transmitter,args=(sock,args.iface))
    
    raw_rx_thread.start()
    raw_tx_thread.start()
    raw_rx_thread.join()
    raw_tx_thread.join()
   
