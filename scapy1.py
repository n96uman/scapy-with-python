from scapy.all import *
'''
def you(packets):
    print(packets)
    wrpcap("pcap_file.pcap",packets)

sniff(filter="port 53",count=10,prn=you)'''

packers=rdpcap("pcap_file.pcap")

for pack in packers:
    print(pack.show)
    print()