from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import time
import threading

ML_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

live_traffic_buffer = []
packet_history = []  
buffer_lock = threading.Lock()

def map_tcp_flags(flags):
    """Maps raw Scapy TCP flags to the KDD dataset 'flag' format."""
    if flags == 'S': return 'S0' # SYN only (Attempted connection)
    if flags == 'R': return 'REJ' # Rejected
    if flags == 'F': return 'SF' # Normal finish
    return 'SF' # Default

def process_packet(packet):
    if IP in packet:
        print(f"[*] Sniffer saw a packet! Source: {packet[IP].src} -> Dest: {packet[IP].dst}") # ADD THIS
    global packet_history
    current_time = time.time()

    # Maintain a 2-second window of packet history for statistical features
    packet_history = [p for p in packet_history if current_time - p['time'] <= 2.0]

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_bytes = len(packet)
        dst_bytes = 0 
        
        flag_str = 'SF'
        service_str = 'private' # Default service
        dst_port = 0
        
        # Protocol and Service Identification
        if packet.haslayer(ICMP):
            protocol_str = "icmp"
            # Detect Ping (ICMP Type 8 is Echo Request)
            if packet[ICMP].type == 8:
                service_str = 'eco_i'
        elif packet.haslayer(UDP):
            protocol_str = "udp"
            dst_port = packet[UDP].dport
        elif packet.haslayer(TCP):
            protocol_str = "tcp"
            flag_str = map_tcp_flags(packet[TCP].flags)
            dst_port = packet[TCP].dport
            # Mapping common ports to services
            if dst_port == 80: service_str = 'http'
            elif dst_port == 22: service_str = 'ssh'
            elif dst_port == 21: service_str = 'ftp'
        else:
            protocol_str = "others"

        # Calculate Traffic Statistics (Crucial for Probe/Ping Sweep detection)
        # count: connections to the same destination host in the last 2 seconds
        count = sum(1 for p in packet_history if p['dst_ip'] == dst_ip)
        
        # srv_count: connections to the same service (or protocol) in the last 2 seconds
        srv_count = sum(1 for p in packet_history if p['protocol'] == protocol_str)

        serror_rate = 1.0 if flag_str == 'S0' else 0.0
        srv_serror_rate = 1.0 if flag_str == 'S0' else 0.0
        same_srv_rate = 1.0 if count > 0 else 0.0
        
        # Update history with current packet details
        packet_history.append({
            'time': current_time, 
            'dst_ip': dst_ip, 
            'protocol': protocol_str,
            'dst_port': dst_port
        })

        # Build the feature dictionary for the ML model
        feature_dict = {col: 0 for col in ML_COLUMNS}

        feature_dict["protocol_type"] = protocol_str
        feature_dict["service"] = service_str
        feature_dict["flag"] = flag_str
        feature_dict["src_bytes"] = src_bytes
        feature_dict["dst_bytes"] = dst_bytes
        feature_dict["count"] = count          
        feature_dict["srv_count"] = srv_count
        
        feature_dict["serror_rate"] = serror_rate
        feature_dict["srv_serror_rate"] = srv_serror_rate
        feature_dict["same_srv_rate"] = same_srv_rate

        # Host-based traffic features
        feature_dict["dst_host_count"] = count
        feature_dict["dst_host_srv_count"] = srv_count
        feature_dict["dst_host_same_srv_rate"] = same_srv_rate
        feature_dict["dst_host_serror_rate"] = serror_rate
        feature_dict["dst_host_srv_serror_rate"] = srv_serror_rate
        
        # Internal field for tracking the source during defense
        feature_dict["_src_ip_"] = src_ip
        
        with buffer_lock:
            live_traffic_buffer.append(feature_dict)

def flush_buffer():
    global live_traffic_buffer
    while True:
        time.sleep(2) # Process collected features every 2 seconds

        with buffer_lock:
            if live_traffic_buffer:
                data_to_save = list(live_traffic_buffer) 
                live_traffic_buffer.clear() 
            else:
                data_to_save = None

        if data_to_save:
            df = pd.DataFrame(data_to_save)
            df.to_csv("outputs/live_features.csv", index=False)

threading.Thread(target=flush_buffer, daemon=True).start()

print("Stateful Flow Sniffer active. Monitoring for ICMP/TCP/UDP traffic...")
# Update the interface name below to match your system exactly
vbox_iface = next((i for i in conf.ifaces.values() if "VirtualBox" in i.description), None)


sniff(prn=process_packet, store=False)