import scapy.all as scapy

# program to check promiscous mode of network interface.
# scan for all network devices using custom ARP packet. If we get response from network then 
# it confirms that the network interface is indeed in promiscous mode.

net_iface = "enp0s3"              # set your interface name
my_mac    = "60:36:DD:98:B6:53"   # set custom source MAC address to be used in ARP packet.
ip_range  = "192.168.0.0/24"      # set IP address range to scan. Use your network IP range.

# Send an ARP request
pkt = scapy.Ether(src=my_mac,dst="FF:FF:FF:FF:FF:FF") / scapy.ARP(pdst=ip_range,hwsrc=my_mac)
ans,unans = scapy.srp(pkt, timeout=2,iface=net_iface)
if ans:
    ans.summary(lambda (s,r): r.sprintf("%Ether.dst% %ARP.psrc%") )

