# 📡 Basic Network Sniffer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Library-Scapy-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
</p>

<p align="center">
  <b>A powerful Python-based network packet sniffer for real-time traffic analysis</b>
</p>

---

## 🚀 Overview

This project is a **basic network packet sniffer** built using **Scapy**. It captures live packets and provides detailed insights into:

- Network protocols
- Packet structure
- Payload data
- Traffic behavior

> 🎓 Developed by DAani Sam for **CodeAlpha Cyber Security Internship – Task 1**

---

## ✨ Features

✅ Real-time packet capture  
✅ Deep protocol analysis (TCP, UDP, ICMP, ARP)  
✅ Payload inspection  
✅ Service detection (HTTP, HTTPS, SSH, etc.)  
✅ Cross-platform compatibility  
✅ Interactive CLI menu  
✅ Packet statistics (rate, duration)

---

## 🖼️ Project Preview

<p align="center">
  <img src="https://github.com/DaniSam-STU/CodeAlpha_Network-Sniffer/blob/main/Screenshots/Screenshot%202026-03-23%20193919.png" width="80%">
</p>

> 📌 After successful cloning and running this output will be generated.

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **Library:** Scapy
- **Concepts:** Networking, Packet Analysis, Cybersecurity

---

## ⚙️ Installation

```bash
git clone https://github.com/DaniSam-STU/CodeAlpha_Network-Sniffer.git
cd network-sniffer
pip install scapy
python network_sniffer.py
```
---
## ▶️ Usage
```
python sniffer.py
```
---
## 📋 Menu Options
1. Capture all packets
2. Capture limited number of packets
3. Capture with filter
4. Capture on specific interface
5. Show available interfaces
6. Exit
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
Source IP: 172.16.2.5
Destination IP: 112.198.27.8
Protocol: 6
Protocol Name: TCP
TTL: 128
Packet Length: 122 bytes

[TCP Layer]
Source Port: 9187
Destination Port: 52376
Flags: PA
Sequence Number: 1076403664
Acknowledgment Number: 2159794780

Payload (first 100 bytes):
b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x18\x00\x05#\x0f2\xad\xa9\xe2\xc6\x93V\x87\xfe\x12\xcc\xb1OVb\x10nk-UW1500-cvU8evy!Bw5Y'
Payload as text: BitTorrent protocol#2ƓV̱OVbnk-UW1500-cvU8evy!Bw5Y

[Ethernet Layer]
Source MAC: 3a:c5:c7:92:b6:fa
Destination MAC: 98:9d:b2:20:48:6f
Ethernet Type: 0x800
```
