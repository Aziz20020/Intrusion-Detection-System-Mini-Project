import time
import re
import threading
import queue
import logging
import tkinter as tk
from collections import defaultdict, deque, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP 
from tkinter import ttk 

# ---- Constants ----
PORT_LIMIT          = 10
PING_LIMIT          = 10
PACKET_LIMIT        = 50
TIME_LIMIT          = 10
TIME_WINDOW         = 60
MAX_ATTEMPTS        = 20
SYN_FLOOD_TRIGGER   = 100
HOST_LIMIT          = 10
MY_IP               = "192.168.165.84"
COMMON_PORTS        = {80, 443, 53, 123, 1900, 22, 21, 445, 3389}
COOLDOWN_TIME       = 4
EXPIRE_TIME         = 120
BUFFER_CLEAN_TIME   = 30
SSH_PORT            = 22
SSH_BRUTE_MAX_ATTEMPTS = 5
SSH_BRUTE_WINDOW    = 60

GATEWAY_IP          = "192.168.165.255"
MY_MAC              = "c8:8a:9a:95:0e:c5"
MAC_FLOOD_LIMIT     = 300
ARP_SCAN_THRESHOLD  = 10
ARP_FLOOD_THRESHOLD = 20
BASELINE_TIME       = 60
WINDOW              = 10

# ---- Flags ----
SYN = 'S'
ACK = 'A'
FIN = 'F'
RST = 'R'
PSH = 'P'
URG = 'U'

# ---- Queues ----
print_que = queue.Queue()
raw_packets    = queue.Queue()
parsed_packets = queue.Queue()
alerts         = queue.Queue()
l2_queue      = queue.Queue()

# ---- Storage Structures ----
tcp_flags         = defaultdict(deque)   # (src,dst) -> (timestamp, port, flags)
udp_packet        = defaultdict(deque)   # (src,dst) -> (timestamp, port)
icmp_pings        = defaultdict(deque)   # src -> (timestamp, dst)
host_sweep        = defaultdict(deque)   # src ->(timestamp, dst, flags, port)
ssh_attempts      = defaultdict(deque)   # (src,dst) -> (timestamp,)
udp_unusual_ports = defaultdict(deque)   # (src,dst) -> (timestamp, port)
failed_attempts   = defaultdict(deque)   # src -> (timestamp,)
# ARP tracking
arp_ip_to_mac           = {}                  # ip → mac
arp_mac_to_ips          = defaultdict(set)    # mac → set of ips
arp_flood_log           = defaultdict(deque)  # mac → deque of timestamps
arp_request_log         = defaultdict(deque)  # mac → deque of (timestamp, target_ip)
mac_activity            = defaultdict(deque)  # mac → deque of timestamps

# ---- Cooldown Trackers ----
last_xmas_alert     = defaultdict(float)
last_fin_alert      = defaultdict(float)
last_null_alert     = defaultdict(float)
last_syn_alert      = defaultdict(float)
last_port_alert     = defaultdict(float)
last_udp_alert      = defaultdict(float)
last_udp_scan_alert = defaultdict(float)
last_icmp_alert     = defaultdict(float)
last_ssh_alert      = defaultdict(float)
last_syn_sweep_alert= defaultdict(float)
last_udp_sweep_alert= defaultdict(float)
arp_alerts          = defaultdict(float)
last_grat_alert     = defaultdict(float)
last_unknown_mac_alert= defaultdict(float)
arp_scan_alerts     = defaultdict(float)

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
trusted_gateway_mac     = None

# baseline
baseline_macs           = set()
baseline_done           = False
baseline_start          = time.time()



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

                    while failed_attempts[src_ip] and (now - failed_attempts[src_ip][0] > TIME_WINDOW):
                        failed_attempts[src_ip].popleft()

                    if len(failed_attempts[src_ip]) > MAX_ATTEMPTS:
                        alerts.put(
                            f"SSH Brute Force from {src_ip} to this machine "
                            f"({len(failed_attempts[src_ip])} failed attempts)"
                        )


def capture(packet):
    raw_packets.put(packet)
    l2_queue.put(packet)


def parse():
    while True:
        packet = raw_packets.get()
        if not packet.haslayer(IP):
            continue

        flags     = set()
        icmp_type = None
        port      = None
        protocol  = "OTHER"
        now       = time.time()

        ip_layer  = packet.getlayer(IP)
        src_ip    = ip_layer.src
        dst_ip    = ip_layer.dst

        tcp_layer  = packet.getlayer(TCP)
        udp_layer  = packet.getlayer(UDP)
        icmp_layer = packet.getlayer(ICMP)

        if tcp_layer:
            flags    = get_flags(tcp_layer)
            protocol = "TCP"
            port     = tcp_layer.dport
        elif udp_layer:
            protocol = "UDP"
            port     = udp_layer.dport
        elif icmp_layer:
            protocol  = "ICMP"
            icmp_type = icmp_layer.type
            port = icmp_type

        print_que.put((src_ip,dst_ip,protocol,port))
        parsed_packets.put((now, port, src_ip, dst_ip, flags, icmp_type, protocol))


def l2_analysis():
    global trusted_gateway_mac, baseline_done

    while True:
        packet = l2_queue.get()
        now    = time.time()

        if not packet.haslayer(Ether):
            continue

        src_mac = packet[Ether].src

        if src_mac == MY_MAC:
            continue

        # ---- MAC Flood Detection (all frames) ----
        mac_activity[src_mac].append(now)
        while mac_activity[src_mac] and mac_activity[src_mac][0] < now - WINDOW:
            mac_activity[src_mac].popleft()

        total_frames = sum(len(v) for v in mac_activity.values())
        if total_frames > MAC_FLOOD_LIMIT:
            if now - arp_alerts[f"macflood_{src_mac}"] > COOLDOWN_TIME:
                alerts.put(f"MAC Flood — {total_frames} frames from {len(mac_activity)} MACs in {WINDOW}s")
                arp_alerts[f"macflood_{src_mac}"] = now

        # ---- Baseline and Unknown MAC (all frames) ----
        if not baseline_done:
            if now - baseline_start < BASELINE_TIME:
                baseline_macs.add(src_mac)
            else:
                baseline_done = True
                alerts.put(f"INFO: Baseline complete — {len(baseline_macs)} known MACs")
        else:
            if src_mac not in baseline_macs:
                if now - last_unknown_mac_alert[src_mac] > COOLDOWN_TIME:
                    alerts.put(f"Unknown MAC after baseline: {src_mac}")
                    last_unknown_mac_alert[src_mac] = now

        if not packet.haslayer(ARP):
            continue

        src_ip   = packet[ARP].psrc
        dst_ip   = packet[ARP].pdst
        arp_type = packet[ARP].op

        # ---- ARP Flood Detection ----
        if packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
            arp_flood_log[src_mac].append(now)
            while arp_flood_log[src_mac] and arp_flood_log[src_mac][0] < now - WINDOW:
                arp_flood_log[src_mac].popleft()
            if len(arp_flood_log[src_mac]) > ARP_FLOOD_THRESHOLD:
                if now - arp_alerts[f"flood_{src_mac}"] > COOLDOWN_TIME:
                    alerts.put(f"ARP Flood from {src_mac} ({len(arp_flood_log[src_mac])} broadcasts in {WINDOW}s)")
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

        # ---- ARP Spoofing Detection (replies only) ----
        if arp_type == 2:
            if src_ip in arp_ip_to_mac and arp_ip_to_mac[src_ip] != src_mac:
                if now - arp_alerts[f"spoof_{src_ip}"] > COOLDOWN_TIME:
                    alerts.put(f"ARP Spoof — {src_ip} was {arp_ip_to_mac[src_ip]} now {src_mac}")
                    arp_alerts[f"spoof_{src_ip}"] = now
            arp_ip_to_mac[src_ip] = src_mac

            # MAC claiming multiple IPs
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

        # ---- ARP Scan Detection (requests only) ----
        if arp_type == 1:
            arp_request_log[src_mac].append((now, dst_ip))
            recent     = [(ts, ip) for ts, ip in arp_request_log[src_mac] if ts > now - TIME_WINDOW]
            unique_ips = {ip for _, ip in recent}
            if len(unique_ips) > ARP_SCAN_THRESHOLD:
                if now - arp_scan_alerts[src_mac] > COOLDOWN_TIME:
                    alerts.put(f"ARP Scan from {src_mac} ({len(unique_ips)} unique IPs in {TIME_WINDOW}s)")
                    arp_scan_alerts[src_mac] = now



def analysis():
    while True:
        packet    = parsed_packets.get()
        now       = packet[0]
        port      = packet[1]
        src_ip    = packet[2]
        dst_ip    = packet[3]
        flags     = packet[4]
        icmp_type = packet[5]
        protocol  = packet[6]

        # ---- Store to structures ----
        if protocol == "TCP":
            host_sweep[src_ip].append((now, dst_ip, protocol))  # tuple, protocol not flags
            if port == SSH_PORT:
                if SYN in flags and ACK not in flags:
                    ssh_attempts[(src_ip, dst_ip)].append(now)
            else:
                tcp_flags[(src_ip, dst_ip)].append((now, port, flags))

        elif protocol == "UDP":
            host_sweep[src_ip].append((now, dst_ip, protocol))  # tuple, protocol not flags
            udp_packet[(src_ip, dst_ip)].append((now, port))
            if port <= 1024 and port not in COMMON_PORTS:
                udp_unusual_ports[(src_ip, dst_ip)].append((now, port))

        elif protocol == "ICMP":
            if icmp_type == 8:
                icmp_pings[src_ip].append((now, dst_ip))

        # ---- Detections ----
        if protocol == "TCP":

            # TCP host sweep
            if now - last_syn_sweep_alert[src_ip] > COOLDOWN_TIME:
                distinct_tcp_hosts = set(dst for t, dst, proto in host_sweep[src_ip]
                                        if proto == "TCP" and t > now - TIME_LIMIT)
                if len(distinct_tcp_hosts) > HOST_LIMIT:
                    alerts.put(f"TCP Host Sweep from {src_ip} ({len(distinct_tcp_hosts)} hosts)")
                    last_syn_sweep_alert[src_ip] = now

            if port != SSH_PORT:

                # XMAS scan
                if now - last_xmas_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    if {FIN, PSH, URG}.issubset(flags):
                        alerts.put(f"XMAS scan from {src_ip} → {dst_ip}")
                        last_xmas_alert[(src_ip, dst_ip)] = now

                # FIN scan
                if now - last_fin_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    if flags == {FIN}:
                        alerts.put(f"FIN scan from {src_ip} → {dst_ip}")
                        last_fin_alert[(src_ip, dst_ip)] = now

                # NULL scan
                if now - last_null_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    if not flags:
                        alerts.put(f"NULL scan from {src_ip} → {dst_ip}")
                        last_null_alert[(src_ip, dst_ip)] = now

                # SYN flood
                if now - last_syn_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    syn_count = sum(1 for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                    if f == {SYN} and t > now - TIME_LIMIT)
                    distinct_ports = set(p for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                        if f == {SYN} and t > now - TIME_LIMIT)
                    if syn_count > SYN_FLOOD_TRIGGER and len(distinct_ports) <= 3:
                        alerts.put(f"SYN Flood from {src_ip} → {dst_ip} ({syn_count} SYNs)")
                        last_syn_alert[(src_ip, dst_ip)] = now

                # SYN scan
                if now - last_port_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    distinct_ports = set(p for t, p, f in tcp_flags[(src_ip, dst_ip)]
                                        if f == {SYN} and t > now - TIME_LIMIT)
                    if len(distinct_ports) > PORT_LIMIT:
                        alerts.put(f"SYN Scan from {src_ip} → {dst_ip} ({len(distinct_ports)} ports)")
                        last_port_alert[(src_ip, dst_ip)] = now

            else:

                # SSH brute force
                if now - last_ssh_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                    recent = [t for t in ssh_attempts[(src_ip, dst_ip)]
                            if t > now - SSH_BRUTE_WINDOW]
                    if len(recent) > SSH_BRUTE_MAX_ATTEMPTS:
                        alerts.put(f"SSH Brute Force from {src_ip} → {dst_ip} ({len(recent)} attempts)")
                        last_ssh_alert[(src_ip, dst_ip)] = now

        elif protocol == "UDP":

            # UDP flood
            if now - last_udp_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                ports_count = Counter(p for t, p in udp_packet[(src_ip, dst_ip)]
                                    if t > now - TIME_LIMIT)
                if ports_count:
                    max_port  = max(ports_count, key=ports_count.get)
                    max_count = ports_count[max_port]
                    if max_count > PACKET_LIMIT:
                        alerts.put(f"UDP Flood from {src_ip} → {dst_ip} ({max_count} packets to port {max_port})")
                        last_udp_alert[(src_ip, dst_ip)] = now

            # UDP host sweep
            if now - last_udp_sweep_alert[src_ip] > COOLDOWN_TIME:
                distinct_udp_hosts = set(dst for t, dst, proto in host_sweep[src_ip]
                                        if proto == "UDP" and t > now - TIME_LIMIT)
                if len(distinct_udp_hosts) > HOST_LIMIT:
                    alerts.put(f"UDP Host Sweep from {src_ip} ({len(distinct_udp_hosts)} hosts)")
                    last_udp_sweep_alert[src_ip] = now

            # UDP scan
            if now - last_udp_scan_alert[(src_ip, dst_ip)] > COOLDOWN_TIME:
                distinct_udp = set(p for t, p in udp_packet[(src_ip, dst_ip)]
                                if t > now - TIME_LIMIT)
                if len(distinct_udp) > PORT_LIMIT:
                    alerts.put(f"UDP Scan from {src_ip} → {dst_ip} ({len(distinct_udp)} ports)")
                    last_udp_scan_alert[(src_ip, dst_ip)] = now

        elif protocol == "ICMP":

            # ping sweep
            if now - last_icmp_alert[src_ip] > COOLDOWN_TIME:
                pings_count = len(set(dst for t, dst in icmp_pings[src_ip]
                                    if t > now - TIME_LIMIT))
                if pings_count > PING_LIMIT:
                    alerts.put(f"Ping sweep from {src_ip} ({pings_count} hosts)")
                    last_icmp_alert[src_ip] = now


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
            while entries and entries[0][0] < now - EXPIRE_TIME:
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

        # add these to clean_expired_entries
        for src_mac, entries in list(arp_flood_log.items()):
            while entries and entries[0][0] < now - EXPIRE_TIME:
                entries.popleft()

        for src_mac, entries in list(mac_activity.items()):
            while entries and entries[0] < now - EXPIRE_TIME:
                entries.popleft()

        
        time.sleep(BUFFER_CLEAN_TIME)


def report_to_terminal():
    while True:
        alert = alerts.get()
        window.after(0,lambda v = alert :warning_list.insert(0,v))
        


def write():
    while True:
        pk = print_que.get()
        packet_recived.insert("",0,values=(pk[0],pk[1],pk[2],pk[3]))    


def sniffer():
    print("Monitoring traffic...")
    sniff(iface='wlp0s20f3', promisc=True, prn=capture,store=False)


# ----------------------------------------------------------------

logging.info("IDS started successfully.")

parse_thread               = threading.Thread(target=parse,daemon=True)
analysis_thread            = threading.Thread(target=analysis,daemon=True)
auth_log_thread            = threading.Thread(target=read_auth_log_file,daemon=True)
clean_thread               = threading.Thread(target=clean_expired_entries,daemon=True)
report_thread              = threading.Thread(target=report_to_terminal,daemon=True)
l2_thread                  = threading.Thread(target=l2_analysis,daemon=True)
print_thread               = threading.Thread(target=write,daemon=True)
sniffer_thread             = threading.Thread(target=sniffer,daemon=True)

window = tk.Tk()
window.title("Ids")
s = ttk.Style()

s.theme_use("clam")
s.configure("ip.Treeview",
            background="grey",
            relief="groove",
            borderwidth=1
            )
s.configure("ip.Treeview.Heading",
            relief="flat"
            )

warning_list = tk.Listbox(window,width=55)



packet_recived = ttk.Treeview(window, columns=("src_Ip", "dst_Ip", "protocol", "port"), show="headings", height= 20,style="ip.Treeview")

packet_recived.heading("src_Ip",text="src_Ip",)
packet_recived.heading("dst_Ip",text="dst_Ip")
packet_recived.heading("protocol",text="protocol")
packet_recived.heading("port",text="port/Icmp type")

packet_recived.column("src_Ip",width=120)
packet_recived.column("dst_Ip",width=120)
packet_recived.column("protocol",width=80)
packet_recived.column("port",width=150)

window.grid_rowconfigure(1,weight=1)
window.grid_columnconfigure(0,weight=2)
window.grid_columnconfigure(2,weight=1)

packet_recived.grid(row=1,column=0,sticky="nsew")

warning_list.grid(row=1,column=2,columnspan=2,sticky="nsew")

print_thread.start()
parse_thread.start()
l2_thread.start()
analysis_thread.start()
auth_log_thread.start()
clean_thread.start()
report_thread.start()
sniffer_thread.start()


window.mainloop()