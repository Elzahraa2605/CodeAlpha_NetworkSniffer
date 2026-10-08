import argparse
from collections import Counter
from datetime import datetime

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, Raw, sniff, wrpcap

stats, saved = Counter(), []


def payload_preview(pkt, limit=60):
    if Raw not in pkt:
        return ""
    data = bytes(pkt[Raw].load)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def describe(pkt):
    if ARP in pkt:
        op = "who-has" if pkt[ARP].op == 1 else "is-at"
        return "ARP", pkt[ARP].psrc, pkt[ARP].pdst, op
    layer = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if layer is None:
        return "OTHER", "?", "?", pkt.summary()
    src, dst = layer.src, layer.dst
    if TCP in pkt:
        t = pkt[TCP]
        ports = (t.sport, t.dport)
        proto = "HTTP" if 80 in ports else "HTTPS" if 443 in ports else "TCP"
        return proto, f"{src}:{t.sport}", f"{dst}:{t.dport}", f"flags={t.flags}"
    if UDP in pkt:
        u = pkt[UDP]
        extra = ""
        if DNS in pkt and pkt[DNS].qd:
            extra = "query=" + pkt[DNS].qd.qname.decode(errors="ignore")
        return ("DNS" if DNS in pkt else "UDP"), f"{src}:{u.sport}", f"{dst}:{u.dport}", extra
    if ICMP in pkt:
        return "ICMP", src, dst, f"type={pkt[ICMP].type}"
    return "IP", src, dst, f"proto={getattr(layer, 'proto', getattr(layer, 'nh', '?'))}"


def handle(pkt, args):
    proto, src, dst, extra = describe(pkt)
    stats[proto] += 1
    if args.write:
        saved.append(pkt)
    print(f"[{datetime.now():%H:%M:%S}] {proto:<5} {src} -> {dst} | len={len(pkt)} {extra}")
    if not args.no_payload and (preview := payload_preview(pkt)):
        print(f"           payload: {preview}")


def main():
    p = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    p.add_argument("-i", "--iface", help="network interface (default: Scapy's default)")
    p.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    p.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    p.add_argument("--no-payload", action="store_true", help="hide payload preview")
    args = p.parse_args()

    print("Sniffing... press Ctrl+C to stop\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None, count=args.count,
              store=False, prn=lambda pkt: handle(pkt, args))
    except PermissionError:
        raise SystemExit("Permission denied: run as root/Administrator (Windows also needs Npcap).")
    except KeyboardInterrupt:
        pass

    print(f"\n--- Summary: {sum(stats.values())} packets ---")
    for proto, n in stats.most_common():
        print(f"{proto:<6} {n}")
    if args.write and saved:
        wrpcap(args.write, saved)
        print(f"Saved to {args.write}")


if __name__ == "__main__":
    main()