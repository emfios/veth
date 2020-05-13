import argparse
import threading
import socket
import struct
from scapy.all import *

def raw_receiver(sock, iface, udp_dst):
    print("raw_receiver")
    print(iface)

    def sniff_callback(pkt):
        #print("r")
        #pkt.show(dump=False)
        #print(pkt.sprintf("SRC:%Ether.src% DST:%Ether.dst% Type: %Ether.type%"))
        if (not pkt.haslayer(Ether)):
            print("not a Ether packet")
            return
        #print(pkt.sprintf("SR2:%Ether.src% DST:%Ether.dst% Type: %Ether.type%"))
        dst = pkt[Ether].dst
        dst = dst.upper()
        #print(dst.upper())
        #if (dst == "7a:67:d7:d0:75:64" or dst == "FF:FF:FF:FF:FF:FF"):
        if (dst == "60:36:DD:98:B6:53" or dst == "FF:FF:FF:FF:FF:FF"):
        #if True:
            #print(pkt.sprintf("SRC:%Ether.src% DST:%Ether.dst% Type: %Ether.type%"))
            #pkt[Ether].dst = "12:34:56:78:9A:BC"
            sock.sendto(bytes(pkt),udp_dst)
        
    sniff(prn=sniff_callback, store=0, iface=iface)
    
def raw_transmitter(sock,iface):
    print("raw_transmitter")
    print(iface)

    # read from udp and send it to scapy
    while True:
        data,addr = sock.recvfrom(65535)
	print(len(data))
        if data:
            pkt = Ether(data)
            #pkt[Ether].src = "08:00:27:5C:39:DC"
            #print(pkt[Ether].src)
            sendp(pkt,iface=iface);
    sock.close()

def display_iface():
    print(" Interface List:")
    list = get_windows_if_list()
    for l in list:
        print((l['name'] + " [" + l['description']) + "]")
        #print(l['ips'])
        
if __name__ == "__main__":
    # Parse the command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', '-i', required=True)
    parser.add_argument('--local_ipaddr', '-l', required=False)
    parser.add_argument('--dst_ipaddr','-t',required=True)
    parser.add_argument('--local_udpport', '-s', required=False, default=8000, type=int)
    parser.add_argument('--dst_udpport', '-d', required=False, default=9000, type=int)
    args = parser.parse_args()
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.local_ipaddr,args.local_udpport))
    
    raw_rx_thread = threading.Thread(target=raw_receiver,args=(sock,args.iface,(args.dst_ipaddr, args.dst_udpport)))
    raw_tx_thread = threading.Thread(target=raw_transmitter,args=(sock,args.iface))
    
    raw_rx_thread.start()
    raw_tx_thread.start()
    raw_rx_thread.join()
    raw_tx_thread.join()
   
