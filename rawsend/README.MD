
Setup
-----
install Python

    sudo apt-get install python3

install scapy

    sudo apt-get install scapy

set promiscuous mode

    sudo ifconfig enp0s3 promisc

Usage
-----
start scan

    sudo python rawsend.py

<pre>Begin emission:
*Finished sending 256 packets.
........
Received 9 packets, got 1 answers, remaining 255 packets
60:36:dd:98:b6:53 192.168.0.7
</pre>

Notes
-----
<pre>
If using VirtualBox, configure network adapter as 'Bridged Adapter' and make sure in 'Advanced:Promiscuous Mode', 'Allow All' is selected.
</pre>

