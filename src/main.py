import sys

from sniffer import PacketSniffer
from parser import PacketParser
from analyzer import TrafficAnalyzer
from detector import ThreatDetector
from reporter import ReportGenerator


def main(pcap_file):
    print("\n===== NETWORK TRAFFIC ANALYZER STARTED =====\n")

    # 1. Load packets from PCAP
    sniffer = PacketSniffer(pcap_file=pcap_file)
    raw_packets = sniffer.load_pcap()

    # 2. Parse packets
    parser = PacketParser(raw_packets)
    parsed_packets = parser.parse()

    # 3. Analyze traffic
    analyzer = TrafficAnalyzer(parsed_packets)
    stats = analyzer.analyze()
    analyzer.print_summary()

    # 4. Detect threats
    detector = ThreatDetector(parsed_packets)
    alerts = detector.run_detection()
    detector.print_alerts()

    # 5. Generate reports
    reporter = ReportGenerator(stats, alerts)
    reporter.export_json()
    reporter.export_csv()

    print("Stats type:", type(stats))
    print("Alerts type:", type(alerts))
    print("Packets loaded:", len(raw_packets))

    print("\n===== ANALYSIS COMPLETE =====")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 src/main.py <path_to_pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)