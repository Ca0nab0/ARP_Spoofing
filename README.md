# Objetivo del script.

Suplantar al Router y a dispositivo final sirviendo como intermediario para capturar el trafico entre estos. Con este script podemos analizar en la misma terminal el trafico que envia el objetivo al router.

Video ilustrativo:  https://youtu.be/jEswLxYMfo4


# Capturas de pantalla.

- Ejecucion


<img width="674" height="65" alt="image" src="https://github.com/user-attachments/assets/7334913b-3f4d-4365-a626-1909f30612f2" />


- Trafico


<img width="840" height="441" alt="image" src="https://github.com/user-attachments/assets/aac20d5a-6b17-4167-8ddb-7d0fbafdca7f" />


<img width="589" height="222" alt="image" src="https://github.com/user-attachments/assets/c754cf8d-e7f0-4c12-8549-fb743ba92f98" />

- En la maquina atacante

<img width="791" height="336" alt="image" src="https://github.com/user-attachments/assets/09526620-5033-4bd4-a82d-b41ec0f2f39e" />


# Topología (interfaces, VLANs, direccionamiento IP), etc..



<img width="428" height="240" alt="image" src="https://github.com/user-attachments/assets/a0cdd55d-aeee-46f5-9a5a-fc73742d48e2" />




<img width="865" height="97" alt="image" src="https://github.com/user-attachments/assets/ac2ecb97-ef46-43f9-a8bb-a06085ac1174" />


# Parámetros usados.

- ip_victima (entrada manual)
- ip_gateway (entrada manual)
- ARP(op=2) (paquete con la MAC del atacante al router y al objetivo)
- packet_log() para analisis de paquetes
- Raw.load para leer paquetes HTTP
  
# Requisitos para utilizar la herramienta.

- Habilitar IP forwading para que la maquina objetivo pierda su conexion a internet

  echo 1 > /proc/sys/net/ipv4/ip_forward

- Python3
- Scapy
- Permisos root
- Estar en la misma red por medio de LAN

# Medidas de mitigación.
- Tabla ARP estatica
  
    enable
  
    configure terminal
  
    arp 192.168.1.10 0050.7966.6800 arpa GigabitEthernet0/0

- Uso de vpn
- Uso de HTTPS/TLS
