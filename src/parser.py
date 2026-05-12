# class used to organize and clean packet data
class PacketParser:
    def __init__(self, packets):
        self.raw_packets = packets
        self.parsed_packets = []

    # parses raw packet information
    def parse(self):
        print("[*] Parsing packets...")

        # loops through all raw packets
        for pkt in self.raw_packets:
            parsed = {
                "timestamp": pkt.get("timestamp"),
                "src_ip": pkt.get("src_ip") or "UNKNOWN",
                "dst_ip": pkt.get("dst_ip") or "UNKNOWN",
                "protocol": pkt.get("protocol") or "UNKNOWN",
                "length": pkt.get("length", 0),

                # NEW FIELDS PASSED THROUGH
                "src_port": pkt.get("src_port"),
                "dst_port": pkt.get("dst_port"),
                "flags": pkt.get("flags")
            }

            self.parsed_packets.append(parsed)

        print(f"[*] Parsed {len(self.parsed_packets)} packets")
        return self.parsed_packets
