from collections import Counter

class TrafficAnalyzer:
    def __init__(self, packets):
        self.packets = packets
        self.stats = {}

    def analyze(self):
        print("[*] Analyzing traffic...")

        src_ips = []
        dst_ips = []
        protocols = []
        total_bytes = 0

        for pkt in self.packets:
            src_ips.append(pkt["src_ip"])
            dst_ips.append(pkt["dst_ip"])
            protocols.append(pkt["protocol"])
            total_bytes += pkt["length"]

        self.stats = {
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "top_source_ips": Counter(src_ips).most_common(5),
            "top_destination_ips": Counter(dst_ips).most_common(5),
            "protocol_distribution": Counter(protocols)
        }

        print("[*] Analysis complete")
        return self.stats

    def print_summary(self):
        print("\n===== TRAFFIC SUMMARY =====")
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Total Bytes: {self.stats['total_bytes']}")

        print("\nTop Source IPs:")
        for ip, count in self.stats["top_source_ips"]:
            print(f"{ip}: {count}")

        print("\nTop Destination IPs:")
        for ip, count in self.stats["top_destination_ips"]:
            print(f"{ip}: {count}")

        print("\nProtocol Distribution:")
        for proto, count in self.stats["protocol_distribution"].items():
            print(f"{proto}: {count}")