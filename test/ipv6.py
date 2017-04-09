from scapy.all import *

sip = '240f:3:8030:1:a00:27ff:fe79:6f83'
dip = '240f:3:8030:1:a65e:60ff:feba:b0b9'

pkt = (IPv6(src=sip, dst=dip) / UDP(sport=50001, dport=50000))

del pkt[UDP].chksum

pkt.show()

send(pkt)
