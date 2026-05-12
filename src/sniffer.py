from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime

# class used to load and process packet capture files
class PacketSniffer:
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = []

    # loads packets from the PCAP file
    def load_pcap(self):
        print(f"[*] Loading PCAP file: {self.pcap_file}")

        raw_packets = rdpcap(self.pcap_file)

        # loops through all captured packets
        for packet in raw_packets:
            pkt_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": None,
                "dst_ip": None,
                "protocol": None,
                "length": len(packet),

                # NEW FIELDS
                "src_port": None,
                "dst_port": None,
                "flags": None
            }

            # checks if the packet contains IP data
            if IP in packet:
                pkt_data["src_ip"] = packet[IP].src
                pkt_data["dst_ip"] = packet[IP].dst

                # checks if the packet is using TCP
                if TCP in packet:
                    pkt_data["protocol"] = "TCP"
                    pkt_data["src_port"] = packet[TCP].sport
                    pkt_data["dst_port"] = packet[TCP].dport
                    pkt_data["flags"] = str(packet[TCP].flags)

                # checks if the packet is using UDP
                elif UDP in packet:
                    pkt_data["protocol"] = "UDP"
                    pkt_data["src_port"] = packet[UDP].sport
                    pkt_data["dst_port"] = packet[UDP].dport

                else:
                    pkt_data["protocol"] = "IP"

            self.packets.append(pkt_data)

        print(f"[*] Loaded {len(self.packets)} packets")
        return self.packets
