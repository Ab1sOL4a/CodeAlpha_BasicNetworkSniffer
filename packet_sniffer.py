from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime


packet_count = 0


def analyze_packet(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 60)
    print(f"Packet #{packet_count}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Packet Size: {len(packet)} bytes")

    # ARP packet
    if packet.haslayer(ARP):
        print("Protocol: ARP")
        print(f"Source MAC: {packet[ARP].hwsrc}")
        print(f"Source IP: {packet[ARP].psrc}")
        print(f"Destination MAC: {packet[ARP].hwdst}")
        print(f"Destination IP: {packet[ARP].pdst}")
        print(f"ARP Operation: {packet[ARP].op}")

    # IPv4 packet
    elif packet.haslayer(IP):
        ip = packet[IP]

        print("Protocol: IPv4")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")
        print(f"TTL: {ip.ttl}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Transport Protocol: TCP")
            print(f"Source Port: {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")
            print(f"TCP Flags: {tcp.flags}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Transport Protocol: UDP")
            print(f"Source Port: {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print("Transport Protocol: ICMP")
            print(f"ICMP Type: {icmp.type}")
            print(f"ICMP Code: {icmp.code}")

    # IPv6 packet
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]

        print("Protocol: IPv6")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")
        print(f"Hop Limit: {ip.hlim}")

    else:
        print("Protocol: Unknown")

    # Display payload information when available
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)

        print(f"Payload Length: {len(payload)} bytes")

        try:
            preview = payload[:100].decode("utf-8", errors="replace")
            print(f"Payload Preview: {preview}")
        except Exception:
            print("Payload Preview: Binary data")
    else:
        print("Payload: None")


def main():
    print("=" * 60)
    print("BASIC NETWORK SNIFFER")
    print("=" * 60)
    print("Capturing network packets...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(prn=analyze_packet, store=False)

    except PermissionError:
        print("\nPermission denied.")
        print("Run the program with administrator/root privileges.")

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped.")
        print(f"Total packets captured: {packet_count}")

    except Exception as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
