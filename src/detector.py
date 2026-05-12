from collections import Counter, defaultdict

# class for detecting suspicious network activity
class ThreatDetector:
    def __init__(self, packets):
        self.packets = packets
        self.alerts = []

    # checks for possible flooding activity
    def detect_ip_flooding(self, threshold=20):
        print("[*] Checking for IP flooding...")

        src_counts = Counter(pkt["src_ip"] for pkt in self.packets)

        for ip, count in src_counts.items():
            if count > threshold:
                alert = {
                    "type": "IP_FLOODING",
                    "ip": ip,
                    "packet_count": count,
                    "severity": "HIGH"
                }
                self.alerts.append(alert)

    # checks for possible port scanning behavior
    def detect_port_scan(self, threshold=10):
        print("[*] Checking for port scan behavior...")

        ip_ports = defaultdict(set)

        for pkt in self.packets:
            src = pkt["src_ip"]
            dst = pkt["dst_ip"]

            # we simulate "port scan behavior" using dst_ip variety
            ip_ports[src].add(dst)

        for ip, targets in ip_ports.items():
            if len(targets) > threshold:
                alert = {
                    "type": "POSSIBLE_PORT_SCAN",
                    "ip": ip,
                    "unique_targets": len(targets),
                    "severity": "MEDIUM"
                }
                self.alerts.append(alert)

    # runs all detection checks
    def run_detection(self):
        print("[*] Running threat detection engine...")

        self.detect_ip_flooding()
        self.detect_port_scan()

        print(f"[*] Detection complete. Alerts found: {len(self.alerts)}")
        return self.alerts

    # displays all detected alerts
    def print_alerts(self):
        print("\n===== SECURITY ALERTS =====")

        if not self.alerts:
            print("No threats detected.")
            return

        for alert in self.alerts:
            print(f"[{alert['severity']}] {alert['type']} - {alert['ip']}")
