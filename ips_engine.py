from scapy.all import sniff, IP, TCP,conf
from database import log_event, init_db
conf.L3socket = conf.L3Rawsocket
# Counter tracking dictionary
syn_tracker = {}

def process_packet(packet):
    # Network layer check (IP + TCP)
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        
        # Check SYN flag for connection attempts
        if packet[TCP].flags == 'S':
            syn_tracker[src_ip] = syn_tracker.get(src_ip, 0) + 1
            
            # Threshold Rule: Agar 1 IP se > 30 SYN requests aati hain
            if syn_tracker[src_ip] > 30:
                print(f"[🚨 IPS ALERT] Intrusion Detected! Blocking IP: {src_ip}")
                
                # Database mein event log karein
                log_event(src_ip=src_ip, attack_type="SYN Flood / DoS Attack", action="BLOCKED")
                
                # Reset counter for that IP
                syn_tracker[src_ip] = 0

def start_engine():
    init_db()
    print("==================================================")
    print("🛡️  IPS NETWORK ENGINE IS RUNNING (SNIFFING)...   ")
    print("==================================================")
    # Packets sniff karein bina memory overfill kiye (store=0)
    sniff(prn=process_packet, store=0)

if __name__ == '__main__':
    start_engine()