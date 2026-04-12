import time
import re
import threading
import queue
import logging
from collections import defaultdict, deque, Counter
from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP,sr1,DNS
import pcapy
import ipaddress

from interface_detect import choose_interface, auto_detect_interface

mode = input("Auto detect interface? (y/n): ")

if mode.lower() == "y":
    dev = auto_detect_interface()
else:
    dev = choose_interface()

print("Using interface:", dev)


# ---- Constants ----
PORT_LIMIT          = 10
PING_LIMIT          = 10
PACKET_LIMIT        = 50
TIME_LIMIT          = 10
TIME_WINDOW         = 60

UDP_SCAN_TRIGGER    = 60
UDP_SCAN_WINDOW     = 30

UDP_FLOOD_TRIGGER   = 300
UDP_FLOOD_WINDOW    = 1 

UDP_SWEEP_LIMIT     = 30
UDP_SWEEP_WINDOW    = 5

DNS_FLOOD_TRIGGER   = 350
DNS_FLOOD_WINDOW    = 5

DNS_ANY_TYPE_TRIGGER = 10
DNS_ANY_TYPE_WINDOW  = 10

SYN_FLOOD_TRIGGER   = 120
SYN_FLOOD_WINDOW    = 1

SYN_SCAN_TRIGGER    = 25
SYN_SCAN_WINDOW     = 5

ICMP_SWEEP_LIMIT    = 15
ICMP_SWEEP_WINDOW   = 5

ICMP_FLOOD_TRIGGER  = 50
ICMP_FLOOD_WINDOW   = 5

TCP_HOST_SWEEP_LIMIT= 30
TCP_HOST_SWEEP_WINDOW=5

MAC_FLOOD_WINDOW    = 5
MAC_FLOOD_TRIGGER   = 50

DNS_RESPONSES_EXPIRE_TIME = 6
DNS_AMPLIFICATION_TRIGGER = 15

DNS_TYPES = {
    1: "A",      # IPv4 address
    2: "NS",     # Name Server
    5: "CNAME",  # Alias
    15: "MX",    # Mail Exchange
    16: "TXT",   # Text records
    28: "AAAA",  # IPv6 address
    255: "ANY"   # The "Amplification" favorite
}



MY_IP               = "10.42.0.1"
COMMON_PORTS        = {80, 443, 53, 123, 1900, 22, 21, 445, 3389}
COOLDOWN_TIME       = 4
EXPIRE_TIME         = 120
BUFFER_CLEAN_TIME   = 30

SSH_PORT            = 22
SSH_BRUTE_MAX_ATTEMPTS = 7
SSH_BRUTE_WINDOW    = 60

SUBNET              = "192.168.0.0/24"

GATEWAY_IP          = "10.42.0.1"
MY_MAC              = "c8:8a:9a:95:0e:c5"
MAC_FLOOD_LIMIT     = 300
ARP_SCAN_THRESHOLD  = 10

ARP_FLOOD_THRESHOLD = 100
ARP_FLOOD_WINDOW    = 1

BASELINE_TIME       = 10 #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
WINDOW              = 10

# ---- Flags ----
SYN = 'S'
ACK = 'A'
FIN = 'F'
RST = 'R'
PSH = 'P'
URG = 'U'

# ---- Queues ----
raw_packets    = queue.Queue(maxsize=5000)
parsed_packets = queue.Queue()
alerts         = queue.Queue()
l2_queue       = queue.Queue(maxsize=5000)

# ---- Storage Structures ----
tcp_flags         = defaultdict(deque)
udp_packet        = defaultdict(deque)
icmp_pings        = defaultdict(deque)
dns_requests      = defaultdict(deque)
host_sweep        = defaultdict(deque)
ssh_attempts      = defaultdict(deque)
udp_unusual_ports = defaultdict(deque)
failed_attempts   = defaultdict(deque)
any_type_dns_count= defaultdict(deque)

arp_ip_to_mac     = {}
known_devices     = {}
dns_queries       = defaultdict(deque)
suspicious_dns_responses = defaultdict(deque)
arp_mac_to_ips          = defaultdict(set)
arp_flood_log           = defaultdict(deque)
arp_request_log         = defaultdict(deque)
mac_activity      = deque()
total_frames            = defaultdict(float)


# ---- Cooldown Trackers ----
last_xmas_alert        = defaultdict(float)
last_fin_alert         = defaultdict(float)
last_null_alert        = defaultdict(float)
last_syn_alert         = defaultdict(float)
last_port_alert        = defaultdict(float)
last_udp_alert         = defaultdict(float)
last_udp_scan_alert    = defaultdict(float)
last_icmp_alert        = defaultdict(float)
last_icmp_flood_alert  = defaultdict(float)
last_ssh_alert         = defaultdict(float)
last_syn_sweep_alert   = defaultdict(float)
last_udp_sweep_alert   = defaultdict(float)
arp_alerts             = defaultdict(float)
last_grat_alert        = defaultdict(float)
last_unknown_mac_alert = defaultdict(float)
arp_scan_alerts        = defaultdict(float)
last_dns_flood_alert   = defaultdict(float)
last_mac_flood_alert   = 0.0
last_dns_amplification_alert = 0.0



showed              = False

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('Sniffer.log', mode='a'),
        logging.StreamHandler()
    ]
)

# gateway
trusted_gateway_mac = None

# baseline
baseline_macs  = set()
macs           = set()
baseline_done  = False
baseline_start = time.time()


# ----------------------------------------------------------------


def get_flags(tcp_layer):
    flags = set()
    if SYN in tcp_layer.flags: flags.add(SYN)
    if RST in tcp_layer.flags: flags.add(RST)
    if ACK in tcp_layer.flags: flags.add(ACK)
    if FIN in tcp_layer.flags: flags.add(FIN)
    if PSH in tcp_layer.flags: flags.add(PSH)
    if URG in tcp_layer.flags: flags.add(URG)
    return flags


def read_auth_log_file():
    try:
        with open("/var/log/auth.log", "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                if "Failed password" in line:
                    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        src_ip = match.group(1)
                        now = time.time()
                        failed_attempts[src_ip].append(now)
                        while failed_attempts[src_ip] and (now - failed_attempts[src_ip][0] > SSH_BRUTE_WINDOW):
                            failed_attempts[src_ip].popleft()
                        if len(failed_attempts[src_ip]) > SSH_BRUTE_MAX_ATTEMPTS:
                            alerts.put(
                                f"SSH Brute Force from {src_ip} to this machine "
                                f"({len(failed_attempts[src_ip])} failed attempts)"
                            )
    except FileNotFoundError:
        logging.info("auth.log not found — skipping SSH log monitoring")


def capture(hdr,data):
    packet = Ether(data, _internal=1)
    
    try:
        
        l2_queue.put(packet)
    except queue.Full:
        pass #Drop packet if full no erro no crash
    try:
        if packet.type == 0x0800:   # IPv4 only
            raw_packets.put(packet)
           
    except queue.Full:
        pass
    



def parse():
    while True:
        
        packet = raw_packets.get()
     

        flags     = set()
        icmp_type = None
        port      = None
        protocol  = "OTHER"
        now       = time.time()
        tcp_layer = None
        udp_layer = None
        icmp_layer = None
        dns_layer  = None
        dname      = None
        dns_id     = None
        is_response = None
        sport = None
        qtype = None


        ip_layer  = packet[IP]
        
        src_ip    = ip_layer.src
        #if (src_ip==MY_IP):
           # continue
        dst_ip    = ip_layer.dst

        proto     = ip_layer.proto

        if proto == 6:      # TCP
            tcp_layer = packet[TCP]
            flags    = get_flags(tcp_layer)
            protocol = "TCP"
            port     = tcp_layer.dport
           # if port == 53:
                #dns_layer = packet[DNS]
                #dname = dns_layer.qd.qname
                #print(f"DomainName: {dname}")

        elif proto == 17:   # UDP
            udp_layer = packet[UDP]
            protocol = "UDP"
            port     = udp_layer.dport
            sport = udp_layer.sport
            if(port==53 or udp_layer.sport == 53):
                dns_layer = packet[DNS]
                dns_id    = dns_layer.id
                qtype     = dns_layer.qd.qtype
                print(qtype)
                is_response = (dns_layer.qr == 1) or (dns_layer.ancount > 0)
                #is_response = bool(dns_layer.qr )      #is it a response querie = 0 , response = 1
                dname = dns_layer.qd.qname
                #print(f"DomainName: {dname}    ID: {dns_id}     Respone?: {is_response}")

        elif proto == 1:    # ICMP
            icmp_layer = packet[ICMP]
            protocol  = "ICMP"
            icmp_type = icmp_layer.type
            port      = icmp_type
    


        local_ips = ipaddress.ip_network(SUBNET)
        if(ipaddress.ip_address(src_ip) in local_ips):
            source = "Internal traffic"
        else:
            source = "External traffic"
        if(ipaddress.ip_address(dst_ip) in local_ips):
            destination = "Internal traffic"
        else:
            destination = "External traffic"
        
        #if(source == "External traffic" and destination == "External traffic"):
          #  continue

        parsed_packets.put([now, port, src_ip, dst_ip, flags, icmp_type, protocol,source,destination,dname,dns_id,is_response,sport,qtype])
        #print(f"src: {src_ip} -> dst: {dst_ip} source {source} destination {destination}")

def baseline_timer():
    global showed,baseline_done

    while not baseline_done:
        now = time.time()
        if now - baseline_start >= BASELINE_TIME:
            baseline_done = True
            alerts.put("INFO: Baseline complete")
        time.sleep(1)  
        

def l2_analysis():
    global trusted_gateway_mac, baseline_done,showed,last_mac_flood_alert

    while True:
        packet = l2_queue.get()
        now    = time.time()

        src_mac = packet.src

        if src_mac == MY_MAC:
            continue
        #print(f"src_mac: {packet.src} -> dst_mac: {packet.dst}")
        # ---- MAC Flood Detection ----
        mac_activity.append((src_mac,now))
        while mac_activity  and mac_activity[0][1] < now - MAC_FLOOD_WINDOW: ##change it to clean thread
            mac_activity.popleft()
            

        
       
        if now - last_mac_flood_alert  > COOLDOWN_TIME:  # make sure cleaning here is same as MAC_FLOOD_WINDOW
            unique_macs = {m for m,t in mac_activity}
            if len(unique_macs)> MAC_FLOOD_TRIGGER:
                alerts.put(f"Possible MAC Flood — {len(unique_macs)} MACs in {MAC_FLOOD_WINDOW}s")
                last_mac_flood_alert = now

        # ---- Baseline and Unknown MAC ----

        #if not showed and baseline_done:
            #showed = True
            #alerts.put(f"INFO: Baseline complete — {len(known_devices)} known MACs")

        if src_mac not in known_devices:
            known_devices[src_mac] = {
                "first_seen": now,
                "ips": set(),
                "alerted": not baseline_done
            }
        
        if packet.type == 0x0800:
            #sr1(IP(dst="10.42.0.5")/ICMP(), timeout=1, verbose=0)
            known_devices[src_mac]["ips"].add(packet[IP].src)
        if baseline_done:
            if not known_devices[src_mac]["alerted"]:
                alerts.put(f"New Device: {src_mac} IPs: {list(known_devices[src_mac]['ips'])}"
)
                known_devices[src_mac]["alerted"] = True
        
        


        if not packet.type==0x0806:  # if not arp skip
            continue

        src_ip   = packet[ARP].psrc
        dst_ip   = packet[ARP].pdst
        arp_type = packet[ARP].op

        # ---- ARP Flood Detection ----
        if packet.dst == "ff:ff:ff:ff:ff:ff":
            arp_flood_log[src_mac].append(now)
            while arp_flood_log[src_mac] and arp_flood_log[src_mac][0] < now - ARP_FLOOD_WINDOW:#move this to clean thread
                arp_flood_log[src_mac].popleft()


            if len(arp_flood_log[src_mac]) > ARP_FLOOD_THRESHOLD:
                if now - arp_alerts[f"flood_{src_mac}"] > COOLDOWN_TIME:
                    alerts.put(f"ARP Flood from {src_mac} ({len(arp_flood_log[src_mac])} broadcasts in {ARP_FLOOD_WINDOW}s)")
                    arp_alerts[f"flood_{src_mac}"] = now

        # ---- Gateway Spoofing Detection ----
        if src_ip == GATEWAY_IP:
            if trusted_gateway_mac is None:
                trusted_gateway_mac = src_mac
                alerts.put(f"INFO: Gateway MAC learned — {src_mac}")
            elif src_mac != trusted_gateway_mac:
                if now - arp_alerts["gateway"] > COOLDOWN_TIME:
                    alerts.put(f"CRITICAL: Gateway spoofing — {GATEWAY_IP} now claims {src_mac}")
                    arp_alerts["gateway"] = now

        # ---- ARP Spoofing Detection ----
        if arp_type == 2:
            if src_ip in arp_ip_to_mac and arp_ip_to_mac[src_ip] != src_mac:
                if now - arp_alerts[f"spoof_{src_ip}"] > COOLDOWN_TIME:
                    alerts.put(f"ARP Spoof — {src_ip} was {arp_ip_to_mac[src_ip]} now {src_mac}")
                    arp_alerts[f"spoof_{src_ip}"] = now
            arp_ip_to_mac[src_ip] = src_mac

            arp_mac_to_ips[src_mac].add(src_ip)
            if len(arp_mac_to_ips[src_mac]) > 3:
                if now - arp_alerts[f"multiip_{src_mac}"] > COOLDOWN_TIME:
                    alerts.put(f"ARP Spoof — {src_mac} claims {len(arp_mac_to_ips[src_mac])} IPs: {arp_mac_to_ips[src_mac]}")
                    arp_alerts[f"multiip_{src_mac}"] = now

            # Gratuitous ARP
            if src_ip == dst_ip and packet[ARP].hwdst in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                if src_ip in arp_ip_to_mac and arp_ip_to_mac[src_ip] != src_mac:
                    if now - last_grat_alert[src_ip] > COOLDOWN_TIME:
                        alerts.put(f"Gratuitous ARP: {src_mac} claiming {src_ip} (was {arp_ip_to_mac[src_ip]})")
                        last_grat_alert[src_ip] = now

        # ---- ARP Scan Detection ----
        if arp_type == 1:
            arp_request_log[src_mac].append((now, dst_ip))
            recent     = [(ts, ip) for ts, ip in arp_request_log[src_mac] if ts > now - TIME_WINDOW]
            unique_ips = {ip for _, ip in recent}
            if len(unique_ips) > ARP_SCAN_THRESHOLD:
                if now - arp_scan_alerts[src_mac] > COOLDOWN_TIME:
                    alerts.put(f"ARP Scan from {src_mac} ({len(unique_ips)} unique IPs in {TIME_WINDOW}s)")
                    arp_scan_alerts[src_mac] = now


def analysis():
    global suspicious_dns_responses, last_dns_amplification_alert
    while True:
        packet    = parsed_packets.get()
        now       = packet[0]
        port      = packet[1]
        src_ip    = packet[2]
        dst_ip    = packet[3]
        flags     = packet[4]
        icmp_type = packet[5]
        protocol  = packet[6]
        dname     = packet[9]
        dns_id    = packet[10]
        is_response = packet[11]
        sport = packet[12]
        qtype = packet[13]

        # ---- Store to structures ----
        if protocol == "TCP":
            host_sweep[src_ip].append((now, dst_ip, protocol))
            tcp_flags[(src_ip, dst_ip)].append((now, port, flags))

        elif protocol == "UDP":
            host_sweep[src_ip].append((now, dst_ip, protocol))
            udp_packet[(src_ip, dst_ip)].append((now, port))
            if port == 53 or sport == 53:
                dns_requests[(src_ip,dst_ip)].append((now,dname))
                if not is_response:
                    dns_queries[dns_id].append(dst_ip)
                else:
                    if(qtype == 255):# ANY type remember to clean this k
                         any_type_dns_count[dst_ip].append(now)
                    if(dns_queries[dns_id]):
                        dns_queries[dns_id].popleft()
                    else:
                        suspicious_dns_responses[dst_ip].append(now)
                        #print(f"--- ADDED TO SUSPICIOUS: {dst_ip} (Total: {len(suspicious_dns_responses[dst_ip])}) ---")

        elif protocol == "ICMP":
            print(f"ICMP packet from {src_ip} to {dst_ip} type {icmp_type}")
            if icmp_type == 8:
                icmp_pings[src_ip].append((now, dst_ip,dname))

        # ---- Detections ----
        if protocol == "TCP":

            if now - last_syn_sweep_alert[src_ip] > COOLDOWN_TIME:
                distinct_tcp_hosts = set(dst for t, dst, proto in host_sweep[src_ip]
                                        if proto == "TCP" and t > now - TCP_HOST_SWEEP_WINDOW)
                if len(distinct_tcp_hosts) > TCP_HOST_SWEEP_LIMIT:
                    alerts.put(f"TCP Host Sweep from {src_ip} ({len(distinct_tcp_hosts)} hosts)")
                    last_syn_sweep_alert[src_ip] = now

           

            if now - last_xmas_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                if {FIN, PSH, URG}.issubset(flags):
                    alerts.put(f"XMAS scan from {src_ip} → {dst_ip}")
                    last_xmas_alert[(src_ip, dst_ip)] = now

            if now - last_fin_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                if flags == {FIN}:
                    alerts.put(f"FIN scan from {src_ip} → {dst_ip}")
                    last_fin_alert[(src_ip, dst_ip)] = now

            if now - last_null_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                if not flags:
                    alerts.put(f"NULL scan from {src_ip} → {dst_ip}")
                    last_null_alert[(src_ip, dst_ip)] = now

            if now - last_syn_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                syn_count = sum(1 for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                if f == {SYN} and t > now - SYN_FLOOD_WINDOW)
                distinct_ports = set(p for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                    if f == {SYN} and t > now - SYN_FLOOD_WINDOW)
                if syn_count > SYN_FLOOD_TRIGGER and len(distinct_ports) <= 3:
                    alerts.put(f"SYN Flood from {src_ip} → {dst_ip} ({syn_count} SYNs)")
                    last_syn_alert[(src_ip, dst_ip)] = now

            if now - last_port_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                distinct_ports = set(p for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                    if f == {SYN} and t > now - SYN_SCAN_WINDOW)
                if len(distinct_ports) > SYN_SCAN_TRIGGER:
                    alerts.put(f"SYN Scan from {src_ip} → {dst_ip} ({len(distinct_ports)} ports)")
                    tcp_flags[((src_ip, dst_ip))].clear()
                    last_port_alert[(src_ip, dst_ip)] = now

            

        elif protocol == "UDP":

            if now - last_udp_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                ports_count = Counter(p for t, p in udp_packet[(src_ip, dst_ip)]
                                    if t > now - UDP_FLOOD_WINDOW)
                if ports_count:
                    max_port  = max(ports_count, key=ports_count.get)
                    max_count = ports_count[max_port]
                    if max_count > UDP_FLOOD_TRIGGER:
                        alerts.put(f"UDP Flood from {src_ip} → {dst_ip} ({max_count} packets to port {max_port})")
                        last_udp_alert[(src_ip, dst_ip)] = now

            if now - last_udp_sweep_alert[src_ip] > COOLDOWN_TIME:
                distinct_udp_hosts = set(dst for t, dst, proto in host_sweep[src_ip]
                                        if proto == "UDP" and t > now - UDP_SWEEP_WINDOW)
                if len(distinct_udp_hosts) > UDP_SWEEP_LIMIT:
                    alerts.put(f"UDP Host Sweep from {src_ip} ({len(distinct_udp_hosts)} hosts)")
                    last_udp_sweep_alert[src_ip] = now

            if now - last_udp_scan_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                distinct_udp = set(p for t, p in udp_packet[(src_ip, dst_ip)]
                                if t > now - UDP_SCAN_WINDOW)
                if len(distinct_udp) > UDP_SCAN_TRIGGER:
                    alerts.put(f"UDP Scan from {src_ip} → {dst_ip} ({len(distinct_udp)} ports in {UDP_SCAN_WINDOW}s)")
                    last_udp_scan_alert[(src_ip, dst_ip)] = now


            if now - last_dns_flood_alert[(src_ip,dst_ip)] > COOLDOWN_TIME:
                requests = len(dns_requests[(src_ip,dst_ip)])
                if (requests > DNS_FLOOD_TRIGGER):
                    alerts.put(f"Possible DNS Flood from {src_ip} to {dst_ip} ({requests} requests in {DNS_FLOOD_WINDOW}s)")
                    last_dns_flood_alert[(src_ip,dst_ip)] = now
                
            if now - last_dns_amplification_alert> COOLDOWN_TIME:
                most_frequent_dst_ip = max(suspicious_dns_responses, key=lambda k: len(suspicious_dns_responses[k]), default=None)
                count = len(suspicious_dns_responses[most_frequent_dst_ip])
                if count > DNS_AMPLIFICATION_TRIGGER:
                    alerts.put(f"Possible DNS AMPLIFICATION Flood against {dst_ip} ({count} dns responses without queries)")
                    last_dns_amplification_alert = now
                else:
                    most_frequent_dst_ip = max(any_type_dns_count, key=lambda k: len(any_type_dns_count[k]), default=None)
                    count = len(any_type_dns_count[most_frequent_dst_ip])
                    if count > DNS_ANY_TYPE_TRIGGER:
                        alerts.put(f"Possible DNS AMPLIFICATION Flood against {dst_ip} ({count} dns responses with ANY type)")


        elif protocol == "ICMP":
            print(f"ICMP packet from {src_ip} to {dst_ip}")
            if now - last_icmp_alert[src_ip] > COOLDOWN_TIME:
               
                pings_count = len(set(dst for t, dst in icmp_pings[src_ip]
                                    if t > now - ICMP_SWEEP_WINDOW))
               
                if pings_count > ICMP_SWEEP_LIMIT:
                    alerts.put(f"Ping sweep from {src_ip} ({pings_count} hosts)")
                    last_icmp_alert[src_ip] = now


            if now - last_icmp_flood_alert[src_ip] > COOLDOWN_TIME:
                pings_count = sum(1 for t,_ in icmp_pings[src_ip] if t> now -ICMP_FLOOD_WINDOW) 
                if(pings_count> ICMP_FLOOD_TRIGGER):
                    alerts.put(f"ICMP Flood from {src_ip} → {dst_ip} ({pings_count} pings!)")
                    last_icmp_flood_alert[src_ip]= time.time()
                


def clean_expired_entries():
    while True:
        now = time.time()

        for (src_ip, dst_ip), entries in list(tcp_flags.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for (src_ip, dst_ip), entries in list(udp_packet.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for (src_ip, dst_ip), entries in list(ssh_attempts.items()):
            while entries and entries[0] < now - EXPIRE_TIME:
                entries.popleft()

        for src_ip, entries in list(icmp_pings.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for (src_ip, dst_ip), entries in list(udp_unusual_ports.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for src_ip, entries in list(host_sweep.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for src_mac, entries in list(arp_request_log.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for src_mac, entries in list(arp_flood_log.items()):
            while entries and entries[0] < now - EXPIRE_TIME:
                entries.popleft()

        for (src_ip, dst_ip), entries in list(dns_requests.items()):
            while entries and entries[0][0]< now - EXPIRE_TIME:
                entries.popleft()

        for ip, entries in list(suspicious_dns_responses.items()):
            while entries and entries[0] < now - EXPIRE_TIME:
                entries.popleft()
        




        time.sleep(BUFFER_CLEAN_TIME)


def report_to_terminal():
    while True:
        alert = alerts.get()
        logging.warning(alert)




# Open live capture
snaplen = 65535
promisc = 1
timeout_ms = 1

cap = pcapy.open_live(dev, snaplen, promisc, timeout_ms)
cap.setfilter("ip or arp or icmp")




# Start loop (-1 = infinite)
def capture_th():
    cap.loop(-1, capture)




# ----------------------------------------------------------------

logging.info("IDS started successfully.")

parse_thread    = threading.Thread(target=parse,                 daemon=True)
capture_thread  = threading.Thread(target=capture_th,            daemon=True)
analysis_thread = threading.Thread(target=analysis,              daemon=True)
auth_log_thread = threading.Thread(target=read_auth_log_file,    daemon=True)
clean_thread    = threading.Thread(target=clean_expired_entries, daemon=True)
report_thread   = threading.Thread(target=report_to_terminal,    daemon=True)
l2_thread       = threading.Thread(target=l2_analysis,           daemon=True)
baseline_timer_thread  = threading.Thread(target=baseline_timer, daemon=True)

baseline_timer_thread.start()
capture_thread.start()
parse_thread.start()
l2_thread.start()
analysis_thread.start()
auth_log_thread.start()
clean_thread.start()
report_thread.start()



# Keep main thread alive
while True:
    time.sleep(1)



def backup():

    if now - last_ssh_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
        recent = [t for t in ssh_attempts[(src_ip, dst_ip)]
                if t > now - SSH_BRUTE_WINDOW]
        if len(recent) > SSH_BRUTE_MAX_ATTEMPTS:
            alerts.put(f"SSH Brute Force from {src_ip} → {dst_ip} ({len(recent)} attempts)")
            last_ssh_alert[(src_ip, dst_ip)] = now
