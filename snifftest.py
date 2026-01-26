import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

PORT_LIMIT = 20
PING_LIMIT = 20
PING_TIME_THRESHOLD = 10 
PACKET_LIMIT = 200
TIME_LIMIT = 1
MY_IP = "192.168.0.2"
COMMON_PORTS = {80, 443, 53, 123, 1900, 22, 21, 445, 3389}
COOLDOWN_TIME = 4
BUFFER_CLEAN_TIME = 12

SYN= 'S'
ACK= 'A'
FIN = 'F'
RST = 'R'
PSH = 'P'
URG = 'U'




last_port_alert = defaultdict(float)
last_tcp_alert = defaultdict(float)
last_icmp_alert = defaultdict(float)
last_udp_alert = defaultdict(float)
last_xmas_alert = defaultdict(float)
last_unusual_port_alert = defaultdict(float) #float to start by default 0.0, we use this dectionnairy to store last time an ip sent a report therefore stop spaming and flooding the terminal
last_buffer_cleaned_time = time.time()

connections = defaultdict(deque)          # ip -> deque(timestamp,ports)

tcp_flags = defaultdict(deque)          # ip -> deque(timestamp,port,flag)
udp_packet = defaultdict(deque)         # ip -> deque(timestamp,port)
icmp_pings = defaultdict(deque)        # ip ->deque(timestamp,ip_pinged)



def get_flags(tcp_layer):
    flags = set()
    if SYN in tcp_layer.flags: flags.add(SYN)   
    if RST in tcp_layer.flags: flags.add(RST)        
    if ACK in tcp_layer.flags: flags.add(ACK)   
    if FIN in tcp_layer.flags: flags.add(FIN)       
    if PSH  in tcp_layer.flags: flags.add(PSH)
    return flags   

def clean(ip):
    """Remove timestamps older than TIME_LIMIT seconds"""
    now = time.time()
  
    p = connections[ip]
    r = tcp_flags[ip]
    d = udp_packet[ip]
    g = icmp_pings[ip]
        




    
    while p and p[0][0] < now - BUFFER_CLEAN_TIME:
        p.popleft()
    
    while r and r[0][0] < now - BUFFER_CLEAN_TIME:
        r.popleft()
        
        
    while d and d[0][0] < now - BUFFER_CLEAN_TIME:
        d.popleft()
    
    while g and g[0][0] < now - BUFFER_CLEAN_TIME:
        g.popleft()
    
        
        
        


def report(ip,port):
        now = time.time()
    
        if now - last_port_alert[ip]> COOLDOWN_TIME:
            # ---- Port scanning detection ----
            port_count = len({p for t,p in connections[ip]}) #(timestamp,port)
            if port_count > PORT_LIMIT:
             print(f"{datetime.now()} ALERT: Possible port scanning from IP: {ip} ({port_count} ports)")
            last_port_alert[ip] = now
            
            
        if now - last_tcp_alert[ip] > COOLDOWN_TIME:
            # ---- Packet rate detection ----
            packet_count = len([flag for _ , _, flag in tcp_flags[ip]
                               if flag == SYN])
            if packet_count > PACKET_LIMIT:
                print(f"ALERT: High packet rate from IP: {ip} ({packet_count} packets in {TIME_LIMIT}s POSSIBLE TCP SCAN!)")
            last_tcp_alert[ip]=now
            
        if now - last_icmp_alert[ip] > COOLDOWN_TIME:
            port_count = len(set(dist_ip for _ , dist_ip in icmp_pings[ip]))
            if port_count > PING_LIMIT:
                print(f"ALERT: Too many pings from IP: {ip} ({port_count} pings in {PING_LIMIT}s POSSIBLE ICMP SCAN!)")
            last_icmp_alert[ip]=now
                
            
        if now - last_udp_alert[ip] > COOLDOWN_TIME:
            # ---- Packet rate detection ----
            packet_count = len(set(p for _,p in udp_packet[ip]))
            if packet_count > PACKET_LIMIT:
                print(f"ALERT: High packet rate from IP: {ip} ({packet_count} packets in {TIME_LIMIT}s POSSIBLE UDP SCAN!)")
            last_udp_alert[ip]=now
                
                
       # if now - last_unusualip_[2]rt_alert[ip] > COOLDOWN_TIME:        
        
            #last_unusual_port_alert[ip] = now
            
        if tcp_flags[ip] and SYN in tcp_flags[ip][-1][2] and RST in tcp_flags[ip][-1][2] and not ACK in tcp_flags[ip][-1][2]:#-1 for latest packet we dont wanna check old already checked packet
         print(f'Alert Possible SYN scan(SYN with RST and no ACK) from ip: {ip}!!')
         

            
            
        
            
        
        
        
        
        


def analyze(packet):
    
    if not packet.haslayer(IP):
        return

    
    
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    

    #src_ip !=  "192.168.137.192"
    #dst_ip != MY_IP
    
    tcp_layer = packet.getlayer(TCP)
    udp_layer = packet.getlayer(UDP)
    icmp_layer = packet.getlayer(ICMP)
    
    if src_ip == MY_IP or dst_ip != MY_IP:
        if(dst_ip=='192.168.0.4'):
         print(f"  --------> FILTERED (src={src_ip}, dst={dst_ip}, MY_IP={MY_IP} )")
        return
    
    protocol = "OTHER"
    port = None
    now = time.time()
    

   
    if tcp_layer:
        flags = get_flags(tcp_layer)
       # if(src_ip == '192.168.0.4'):
       # print(f"DEBUG FLAGS from {src_ip} -> {dst_ip}: {flags}")
        protocol = "TCP"  
        port = tcp_layer.dport
        is_service_port = port <= 1024
        is_uncommon = port not in COMMON_PORTS
        tcp_flags[src_ip].append((now,port,flags))
        if last_xmas_alert[src_ip] - now > COOLDOWN_TIME:
            if( (FIN in flags) and (PSH in flags ) and (URG in flags) ) or( (FIN in flags) and ((PSH in flags ) or (URG in flags))) :
                print(f'Alert Possible XMAS scan!! from ip: {src_ip}')
                last_xmas_alert[src_ip] = now
        
        if (flags=={FIN}):
            print(f'Alert Possible FIN scan!! from ip: {src_ip}')
    
        if(not flags):
            print(f'Alert Possible NULL scan (NO FLAGS WITH A TCP PACKET)!! from ip: {src_ip}')
        
        #if (is_service_port and is_uncommon):
             # print(f"ALERT: Unusual port {port} from IP: {src_ip} ")

        
        
    if udp_layer:
        protocol = "UDP"
        port = udp_layer.dport
        is_service_port = port <= 1024
        is_uncommon = port not in COMMON_PORTS
        udp_packet[src_ip].append((now,port))
        if (is_service_port and is_uncommon):
              print(f"{datetime.now()} ALERT: Unusual port {port} from IP: {src_ip} ")
        
    if icmp_layer:
        if icmp_layer.type == 8:  # Echo Request (ping)
            icmp_pings[src_ip].append((now,dst_ip))
        
    
    connections[src_ip].append((now,port))

  

# ---------------------------------------------------------------------------------------------------------------->>>>>>> bs.zaouche@gmail.com 



    # ---- Time window tracking ----

   
    clean(src_ip)
    if(src_ip == '192.168.0.4'):
        print(f"{src_ip} --> {dst_ip} | {protocol} | Port: {port}")
    #print(f"DEBUG FLAGS from {src_ip} -> {flags}")
    

    report(src_ip,port)


print("Monitoring traffic...")
sniff(
    timeout=100,
    prn=analyze
)
#iface='\\Device\\NPF_{55F65FBC-B063-4B21-9C0E-9173F3EDA695}'

#print("\nConnections:", dict(connections))
#print("Packet timestamps:", {ip: len(q) for ip, q in tcp_flags.items()})
#print("Packet timestamps:", {ip: len(q) for ip, q in udp_packet.items()})

