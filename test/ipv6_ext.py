from scapy.all import *

sip = ''
dip = ''

geotype = '\x00'
flags = '\x01'
latint = '\x11\x11'
latfrac = '\x10\x10\x10\x10'
lonfrac = '\x20\x20\x20\x20'
alt = '\x01\x01\x01\x01\x01\x01\x01\x01'
sec = '\x03\x03\x03\x03'
usec = '\x04\x04\x04\x04'

data = geotype + flags + latint + latfrac + lonfrac + alt + sec + usec

pkt = (IPv6(src=sip, dst=dip) / IPv6ExtHdrDestOpt(len=3, options=PadN(otype=30, optlen=28, optdata=data)) / TCP())

pkt.show()

send(pkt)
