import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

PORT_LIMIT = 10
PACKET_LIMIT = 10
TIME_LIMIT = 10
MY_IP = "192.168.0.2"
COMMON_PORTS = {80, 443, 53, 123, 1900, 22, 21, 445, 3389}
COOLDOWN_TIME = 4
BUFFER_CLEAN_TIME = 12


last_port_alert = defaultdict(float)
last_packet_alert = defaultdict(float)
last_unusual_port_alert = defaultdict(float) #float to start by default 0.0, we use this dectionnairy to store last time an ip sent a report therefore stop spaming and flooding the terminal
last_buffer_cleaned_time = time.time()

connections = defaultdict(deque)          # ip -> deque(timestamps,ports)
ip_timestamps = defaultdict(deque)      # ip -> deque(timestamps)


def clean(ip):
    """Remove timestamps older than TIME_LIMIT seconds"""
    now = time.time()
    q = ip_timestamps[ip]
    p = connections[ip]
        



    while q and q[0] < now - TIME_LIMIT:
        q.popleft()
    
    while p and p[0][0] < now - BUFFER_CLEAN_TIME:
        p.popleft()
        
    
        
        
        


def report(ip,common,port):
        now = time.time()
    
        if now - last_port_alert[ip]> COOLDOWN_TIME:
            # ---- Port scanning detection ----
            port_count = len({p for t,p in connections[ip]}) #(timestamp,port)
            if port_count > PORT_LIMIT:
             print(f" ALERT: Possible port scanning from IP: {ip} ({port_count} ports)")
            last_port_alert[ip] = now
            
            
        if now - last_packet_alert[ip] > COOLDOWN_TIME:
            # ---- Packet rate detection ----
            packet_count = len(ip_timestamps[ip])
            if packet_count > PACKET_LIMIT:
                print(f"ALERT: High packet rate from IP: {ip} ({packet_count} packets in {TIME_LIMIT}s)")
            last_packet_alert[ip]=now
                
                
        if now - last_unusual_port_alert[ip] > COOLDOWN_TIME:        
            if(common == False):
                print(f"ALERT: Unusual port {port} from IP: {ip} ")
            last_unusual_port_alert[ip] = now
        
        
        
        


def analyze(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if src_ip == MY_IP:
        return
    tcp_layer = packet.getlayer(TCP)
    udp_layer = packet.getlayer(UDP)
    
    protocol = "OTHER"
    port = None
    common = False
    if tcp_layer is not None or udp_layer is not None:
        if tcp_layer is not None:
            protocol = "TCP"  
            port = tcp_layer.dport
        else:
            protocol = "UDP"
            port = udp_layer.dport
        
        now = time.time()
        connections[src_ip].append((now,port))
        for elm in COMMON_PORTS:
            if elm == port:
                common = True
    
    
        # ---- Time window tracking ----
  
        ip_timestamps[src_ip].append(now)

        clean(src_ip)

        #print(f"{src_ip} --> {dst_ip} | {protocol} | Port: {port}")

        report(src_ip,common,port)


print("Monitoring traffic...")
sniff(
    iface='\\Device\\NPF_{55F65FBC-B063-4B21-9C0E-9173F3EDA695}',
    timeout=10,
    prn=analyze
)

#print("\nConnections:", dict(connections))
print("Packet timestamps:", {ip: len(q) for ip, q in ip_timestamps.items()})
