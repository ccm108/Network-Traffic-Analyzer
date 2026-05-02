import csv
import json
import os

class ReportGenerator:
    def __init__(self, stats, alerts):
        self.stats = stats
        self.alerts = alerts

    def export_json(self, filepath="output/report.json"):
        print("[*] Exporting JSON report...")

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        report = {
            "statistics": self.stats,
            "alerts": self.alerts
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=4)

        print(f"[*] JSON report saved to {filepath}")

    def export_csv(self, filepath="output/report.csv"):
        print("[*] Exporting CSV report...")

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["Type", "IP", "Details", "Severity"])

            for alert in self.alerts:
                if alert["type"] == "IP_FLOODING":
                    writer.writerow([
                        alert["type"],
                        alert["ip"],
                        f"{alert['packet_count']} packets",
                        alert["severity"]
                    ])

                elif alert["type"] == "POSSIBLE_PORT_SCAN":
                    writer.writerow([
                        alert["type"],
                        alert["ip"],
                        f"{alert['unique_targets']} unique targets",
                        alert["severity"]
                    ])

        print(f"[*] CSV report saved to {filepath}")