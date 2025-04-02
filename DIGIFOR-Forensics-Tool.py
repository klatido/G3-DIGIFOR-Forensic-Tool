import scapy.all as scapy
import pyshark
import matplotlib.pyplot as plt
import pandas as pd
import asyncio
import os
import threading


user_desktop = os.path.join(os.path.expanduser("~"), "Desktop")
pcap_path = os.path.join(user_desktop, "exercise-1.pcap")  

cap = pyshark.FileCapture(pcap_path)

class NetworkForensicTool:
    def __init__(self, pcap_filename=None, live_capture=False):
        "Initialize the tool and locate the PCAP file on the Desktop or enable live capture."
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.pcap_file = os.path.join(desktop_path, pcap_filename) if pcap_filename else None
        self.live_capture = live_capture
        self.packets = []
        self.traffic_data = []

   

    def load_pcap(self):
        """Load packets synchronously to avoid event loop issues."""
        if self.live_capture:
            print("Starting live network capture...")
            self.capture_live_traffic()
            return

        if not self.pcap_file or not os.path.exists(self.pcap_file):
            print("PCAP file not found on Desktop.")
            return

        self.load_pcap_sync()  

    def load_pcap_sync(self):
        """Synchronously load packets from the PCAP file."""
        cap = pyshark.FileCapture(self.pcap_file, use_json=True)

        packet_count = 0
        for packet in cap:
            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                timestamp = float(packet.sniff_time.timestamp())

                packet_info = [timestamp, src_ip, dst_ip, protocol]
                print(f"Storing packet {packet_count + 1}: {packet_info}")  
                self.traffic_data.append(packet_info)

                packet_count += 1
            except AttributeError:
                print(f"Skipping packet {packet_count + 1} due to missing IP layer")
                continue

        cap.close()
        print(f"Loaded {packet_count} packets from {self.pcap_file}") 


    def _run_async_task(self):
        """Run packet processing in a separate thread without event loop conflicts."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.load_pcap_sync())  



    def capture_live_traffic(self, interface="eth0", packet_count=50):
        "Capture live network traffic using Scapy."
        print("Capturing live network traffic...")
        packets = scapy.sniff(iface=interface, count=packet_count)
        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet.summary().split()[0]
                timestamp = packet.time
                self.traffic_data.append([timestamp, src_ip, dst_ip, protocol])
        print(f"Captured {len(self.traffic_data)} live packets.")

    def detect_ddos(self, df):
        "Identify potential DDoS attacks based on multiple unique sources targeting one destination."
        if df.empty:
            return pd.DataFrame()

        source_counts = df.groupby('Destination')['Source'].nunique().reset_index(name='num_unique_sources')
        return source_counts[source_counts['num_unique_sources'] > 50]

    def detect_c2_traffic(self, df):
        "Identify potential C2 communication by analyzing frequent, small external connections."
        if df.empty:
            return pd.DataFrame()

        external_ips = df[~df['Destination'].str.startswith(('192.', '10.', '172.'))]
        c2_candidates = external_ips.groupby('Destination').size().reset_index(name='connection_count')
        return c2_candidates[c2_candidates['connection_count'] > 30]

    def detect_data_exfiltration(self, df):
        "Detect potential data exfiltration based on large outbound transfers."
        if df.empty:
            return pd.DataFrame()

        df['Packet_Size'] = df.get('Packet_Size', 0)
        data_transfer = df.groupby('Destination')['Packet_Size'].sum().reset_index(name='Total_Data_Sent')
        return data_transfer[data_transfer['Total_Data_Sent'] > 100 * 1024 * 1024]

    def analyze_traffic(self):
        "Detect anomalies such as beaconing, port scans, ARP spoofing, DDoS, C2 traffic, and data exfiltration."
        if not self.traffic_data:
            print("No traffic data available for analysis.")
            return

        df = pd.DataFrame(self.traffic_data, columns=['Timestamp', 'Source', 'Destination', 'Protocol'])

        print("\nTraffic Summary:")
        print(df.groupby(['Source', 'Destination']).size().reset_index(name='Count').head(10))

        # Detect DDoS
        suspected_ddos = self.detect_ddos(df)
        if not suspected_ddos.empty:
            print("\n🚨 Potential DDoS Attack Detected:")
            print(suspected_ddos)

        # Detect C2 Traffic
        suspicious_c2 = self.detect_c2_traffic(df)
        if not suspicious_c2.empty:
            print("\n⚠️ Suspicious C2 Communication Detected:")
            print(suspicious_c2)

        # Detect Data Exfiltration
        suspicious_exfiltration = self.detect_data_exfiltration(df)
        if not suspicious_exfiltration.empty:
            print("\n🚨 Potential Data Exfiltration Detected:")
            print(suspicious_exfiltration)

        df['Time_Diff'] = df.groupby(['Source', 'Destination'])['Timestamp'].diff()
        beaconing = df.groupby(['Source', 'Destination'])['Time_Diff'].mean().reset_index()
        beaconing = beaconing[beaconing['Time_Diff'] < 5]
        print("\nPotential Beaconing:")
        print(beaconing)

        port_scanning = df.groupby('Source').size().reset_index(name='Count')
        port_scanning = port_scanning[port_scanning['Count'] > 20]
        print("\nPotential Port Scanning:")
        print(port_scanning)

        arp_spoofing = df[df['Protocol'] == 'ARP'].groupby('Source').size().reset_index(name='Count')
        arp_spoofing = arp_spoofing[arp_spoofing['Count'] > 1]
        print("\nPotential ARP Spoofing:")
        print(arp_spoofing)

    def visualize_traffic(self):
        "Generate a visual representation of network activity."
        if not self.traffic_data:
            print("No traffic data available for visualization.")
            return

        df = pd.DataFrame(self.traffic_data, columns=['Timestamp', 'Source', 'Destination', 'Protocol'])

        if df.empty:
            print("No data to visualize.")
            return

        top_talkers = df.groupby('Source').size().nlargest(10)

        if top_talkers.empty:
            print("No significant traffic to visualize.")
            return

        plt.figure(figsize=(10, 5))
        top_talkers.plot(kind='bar', color='blue')
        plt.title("Top 10 Talkers in Network Traffic")
        plt.xlabel("Source IP")
        plt.ylabel("Packet Count")
        plt.show()
        

# Initialize the tool with a test PCAP file
tool = NetworkForensicTool(pcap_path, live_capture=False)


# Load and analyze the traffic
tool.load_pcap()
tool.analyze_traffic()
tool.visualize_traffic()      

