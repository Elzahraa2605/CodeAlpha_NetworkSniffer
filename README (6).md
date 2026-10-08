# CodeAlpha_NetworkSniffer

Basic network sniffer built with Python and [Scapy](https://scapy.net) — CodeAlpha Cyber Security Internship, **Task 1**.

## Features
- Captures live packets from a network interface
- Shows time, protocol, `source -> destination` (IP:port), length, TCP flags / DNS query / ICMP type
- Previews the payload (first 60 printable bytes): readable for plain HTTP, unreadable for HTTPS because it is encrypted
- BPF filters, packet limit, save to `.pcap` (open in Wireshark) and a protocol summary on exit

## Requirements
- Python 3.8+ and `pip install -r requirements.txt`
- Root / Administrator rights (Windows also needs [Npcap](https://npcap.com))

## Usage
```bash
sudo python3 sniffer.py                        # capture until Ctrl+C
sudo python3 sniffer.py -c 20                  # stop after 20 packets
sudo python3 sniffer.py -f "tcp port 80"       # only HTTP traffic
sudo python3 sniffer.py -i wlan0 -w out.pcap   # choose interface + save pcap
sudo python3 sniffer.py --no-payload           # headers only
```
On Windows run the terminal as Administrator and use `python sniffer.py`.

## Output format
```
[14:02:11] DNS   192.168.1.5:5353 -> 8.8.8.8:53 | len=69 query=example.com.
[14:02:11] HTTP  192.168.1.5:51000 -> 93.184.216.34:80 | len=95 flags=PA
           payload: GET / HTTP/1.1..Host: example.com....
```

## How it works
Every frame is a stack of layers: `Ethernet -> IP -> TCP/UDP/ICMP -> application data`.
Scapy parses each layer; `describe()` reads the IP layer (source/destination), the transport layer (ports, flags) and the application layer (DNS query, raw payload), and `handle()` prints and counts it.

## Ethics
Use only on networks you own or have written permission to monitor. Sniffing other people's traffic is illegal.
