### - This project is a Python-based Network Packet Sniffer developed using the Scapy library. It captures live network traffic and analyzes packets in real time to extract useful information such as source and destination IP addresses, protocols, ports, and payload data.
### - The tool supports multiple protocols including TCP, UDP, ICMP, and ARP, and provides detailed layer-wise insights for better understanding of network communication. It also identifies common services like HTTP, HTTPS, SSH, and DNS based on port numbers.
### - Designed with an interactive command-line interface, the sniffer allows users to capture all packets, apply filters, limit packet count, or select specific network interfaces. Additionally, it displays capture statistics such as total packets, duration, and packet rate.
### - This project is useful for beginners in networking and cybersecurity to understand how data flows across networks and how packet analysis works in real-world scenarios.

---
## 📋 Description of Menu Options

The program provides an interactive command-line menu with multiple packet capture modes:

### 🔹 Option 1: Capture All Packets (Default)
Captures all incoming and outgoing network packets without any restrictions.  
This mode is useful for general traffic monitoring and understanding overall network activity.

---

### 🔹 Option 2: Capture Limited Number of Packets
Allows the user to specify the number of packets to capture.  
The sniffer automatically stops after reaching the given limit.  
Useful for testing and controlled analysis.

---

### 🔹 Option 3: Capture with Filter
Enables packet capture based on specific filters (BPF syntax).  
Examples:
- `tcp` → Capture only TCP packets  
- `udp` → Capture only UDP packets  
- `icmp` → Capture ICMP packets  
- `port 80` → Capture HTTP traffic  

This option helps in focusing on specific types of network traffic.

---

### 🔹 Option 4: Capture on Specific Interface
Allows the user to select a particular network interface (e.g., Wi-Fi, Ethernet).  
Useful when multiple network interfaces are available on the system.

---

### 🔹 Option 5: Show Available Interfaces
Displays all available network interfaces on the system along with details.  
Helps the user choose the correct interface for packet capturing.

---

### 🔹 Option 6: Exit
Terminates the program safely.

---

## ⚙️ Additional Functional Features

- **Real-time Packet Processing:** Each captured packet is analyzed instantly  
- **Protocol Detection:** Identifies TCP, UDP, ICMP, ARP  
- **Service Identification:** Detects services like HTTP, HTTPS, SSH, etc.  
- **Payload Analysis:** Displays first 100 bytes of packet payload  
- **Statistics Display:** Shows total packets, duration, and packet rate after stopping capture  
t
---
## 🔍 Filters You Can Use
| Filter | Description |
| ------ | -----------|
| tcp	| TCP packets |
| udp |	UDP packets |
| icmp	| ICMP packets |
| port 80 |	HTTP traffic|
| tcp and port 443 |	HTTPS traffic |
---
## Sample Output
```
[PACKET #1] - 2026-03-23 19:17:00
================================================================================
Source IP: 172.1X.c.p
Destination IP: 112.19x.2c.p
Protocol: 6
Protocol Name: TCP
TTL: 128
Packet Length: 122 bytes

[TCP Layer]
Source Port: 9187
Destination Port: 52376
Flags: PA
Sequence Number: 1076373882
Acknowledgment Number: 2159727234

Payload (first 100 bytes):
b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x18\x00\x05#\x0f2\xad\xa9\xe2\xc6\x93V\x87\xfe\x10nk-UW1500-cvU8evy!Bw5Y'
Payload as text: BitTorrent protocol#2ƓV̱OVbnk-UW1500xcv8bsy!Bw5Y

[Ethernet Layer]
Source MAC: 3a:c5:x7:42:c6:da
Destination MAC: 38:0d:n2:40:09:da
Ethernet Type: 0x800
*this data is for educational purposes only*
```
<p align="center">
  <img src="https://github.com/DaniSam-STU/CodeAlpha_Network-Sniffer/blob/main/Screenshots/Screenshot%202026-03-23%20193919.png" width="80%">
</p>
---

## 🧠 How It Works
- Uses Scapy sniff() to capture packets
- Extracts layers like:
- IP
- TCP / UDP
- ICMP / ARP
- Maps ports → services
- Displays payload (if present)
---

