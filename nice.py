from scapy.all import sniff, Ether, ARP
import time
import datetime

# ================= CONFIG =================

GATEWAY_IP="192.168.0.1"
MY_MAC = "c8:8a:9a:8e:8a:0a"

WINDOW = 10              # seconds
MAX_FRAMES = 300         # MAC flooding threshold
ALERT_COOLDOWN = 30      # seconds
BASELINE_TIME = 60   # seconds
start_time = time.time()
baseline_macs = set()
baseline_done = False



# ================= MEMORY =================

mac_activity = {}        # MAC → timestamps
arp_ip_to_mac = {}       # IP → MAC
arp_mac_to_ips = {}      # MAC → set(IPs)
alert_state = {}         # alert_key → last_time
trusted_gateway_mac = None # learned at runtime
arp_activity = {}   # MAC → ARP timestamps


# ================= ALERT =================

def alert_once(key, msg, severity="HIGH"):
    now = time.time()
    if key in alert_state and now - alert_state[key] < ALERT_COOLDOWN:
        return

    alert_state[key] = now
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    print(f"[{severity}] {ts}: {msg}")
    with open("alerts.log", "a") as f:
        f.write(f"{ts} {severity} {msg}\n")

# ================= EXTRACTION =================

def extract(packet):
    if Ether not in packet:
        return None

    data = {
        "ts": datetime.datetime.now().strftime("%H:%M:%S"),
        "src_mac": packet[Ether].src,
        "dst_mac": packet[Ether].dst,
        "eth_type": hex(packet[Ether].type),
        "arp_ip": None
    }

    if packet.haslayer(ARP):
        data["arp_ip"] = packet[ARP].psrc

    return data

# ================= MEMORY UPDATE =================

def update_mac_activity(mac):
    now = time.time()
    mac_activity.setdefault(mac, []).append(now)
    mac_activity[mac] = [t for t in mac_activity[mac] if now - t <= WINDOW]

# ================= DETECTION =================

def detect_mac_flooding(mac):
    if len(mac_activity[mac]) > MAX_FRAMES:
        alert_once(
            key=f"mac_flood_{mac}",
            msg=f"MAC Flooding detected from {mac} ({len(mac_activity[mac])} frames in {WINDOW}s)"
        )

def detect_arp_spoofing(extracted):
    ip = extracted["arp_ip"]
    mac = extracted["src_mac"]

    if not ip or mac == MY_MAC:
        return

    # IP → MAC (IP takeover)
    if ip in arp_ip_to_mac and arp_ip_to_mac[ip] != mac:
        alert_once(
            key=f"arp_ip_change_{ip}",
            msg=f"ARP Spoofing: IP {ip} changed from {arp_ip_to_mac[ip]} to {mac}"
        )
    arp_ip_to_mac[ip] = mac

    # MAC → IPs (MAC impersonation)
    arp_mac_to_ips.setdefault(mac, set()).add(ip)
    if len(arp_mac_to_ips[mac]) > 1:
        alert_once(
            key=f"arp_multi_ip_{mac}",
            msg=f"ARP Spoofing: MAC {mac} claims multiple IPs {arp_mac_to_ips[mac]}"
        )


def detect_gateway_attack(extracted):
    global trusted_gateway_mac

    ip = extracted["arp_ip"]
    mac = extracted["src_mac"]
    print("ok")

    if ip != GATEWAY_IP:
        return

    if trusted_gateway_mac is None:
        trusted_gateway_mac = mac
        print(f"[INFO] Trusted gateway learned: {mac}")
        return

    if mac != trusted_gateway_mac:
        alert_once(
            key="gateway_spoof",
            msg=f"GATEWAY SPOOFING: {GATEWAY_IP} changed from {trusted_gateway_mac} to {mac}",
            severity="CRITICAL"
        )  



def baseline_learning(mac):
    global baseline_done

    if baseline_done:
        return

    if time.time() - start_time <= BASELINE_TIME:
        baseline_macs.add(mac)
    else:
        baseline_done = True
        print(f"[INFO] Baseline complete. Known MACs: {baseline_macs}")

def detect_unknown_mac(mac):
    if not baseline_done:
        return

    if mac not in baseline_macs:
        alert_once(
            key=f"unknown_mac_{mac}",
            msg=f"New MAC detected after baseline: {mac}",
            severity="LOW"
        )

# ================= PACKET PIPELINE =================

def handle_packet(packet):
    extracted = extract(packet)
    if not extracted:
        return

    if extracted["src_mac"] == MY_MAC:
        return

    update_mac_activity(extracted["src_mac"])
    detect_mac_flooding(extracted["src_mac"])
    detect_arp_spoofing(extracted)
    detect_gateway_attack(extracted)
    baseline_learning(extracted["src_mac"])
    detect_unknown_mac(extracted["src_mac"])



    print(
        f"[{extracted['ts']}] "
        f"{extracted['src_mac']} -> {extracted['dst_mac']} | "
        f"EtherType={extracted['eth_type']} | ARP_IP={extracted['arp_ip']}"
    )

# ================= START =================

print(" Layer-2 IDS started (MAC Flooding + ARP Spoofing)")
print(" Detecting: MAC Flooding | ARP Spoofing | Gateway Attack")
print(" Ctrl+C to stop\n")

sniff(iface='\\Device\\NPF_{4BD157A0-BBF9-4085-BDE2-0416A22FFF58}', prn=handle_packet, store=0)
