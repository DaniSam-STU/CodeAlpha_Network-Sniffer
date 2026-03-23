#!/usr/bin/env python3
"""
Basic Network Sniffer
- By DAani Sam
Captures and analyzes network packets to display protocol information
"""

# Import necessary modules
try:
    from scapy.all import *
except ImportError:
    print("Error: Scapy is not installed.")
    print("Install it using: pip install scapy")
    print("On Linux/macOS, you might need: sudo pip install scapy")
    exit(1)

import sys
import time
import platform
from datetime import datetime

# For Windows compatibility
if platform.system() == 'Windows':
    import os
    # Try to set npcap/windivert compatibility
    try:
        from scapy.arch import windows
    except:
        pass

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.start_time = None
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        print("\n" + "="*80)
        print(f"[PACKET #{self.packet_count}] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        # Check if packet has IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")
            print(f"Protocol: {ip_layer.proto}")
            
            # Protocol identification
            protocol_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                2: "IGMP"
            }
            protocol_name = protocol_map.get(ip_layer.proto, f"Unknown ({ip_layer.proto})")
            print(f"Protocol Name: {protocol_name}")
            print(f"TTL: {ip_layer.ttl}")
            print(f"Packet Length: {len(packet)} bytes")
            
            # TCP Layer Analysis
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                print(f"\n[TCP Layer]")
                print(f"Source Port: {tcp_layer.sport}")
                print(f"Destination Port: {tcp_layer.dport}")
                print(f"Flags: {tcp_layer.flags}")
                print(f"Sequence Number: {tcp_layer.seq}")
                print(f"Acknowledgment Number: {tcp_layer.ack}")
                
                # Identify common services
                service_map = {
                    80: "HTTP",
                    443: "HTTPS",
                    21: "FTP",
                    22: "SSH",
                    25: "SMTP",
                    53: "DNS",
                    110: "POP3",
                    143: "IMAP",
                    3306: "MySQL",
                    3389: "RDP"
                }
                
                if tcp_layer.dport in service_map:
                    print(f"Service: {service_map[tcp_layer.dport]}")
                elif tcp_layer.sport in service_map:
                    print(f"Service: {service_map[tcp_layer.sport]}")
                
                # Show payload if available
                if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                    try:
                        payload = bytes(tcp_layer.payload)
                        if len(payload) > 0:
                            print(f"\nPayload (first 100 bytes):")
                            print(payload[:100])
                            try:
                                text_payload = payload[:100].decode('utf-8', errors='ignore')
                                if text_payload.strip():
                                    print(f"Payload as text: {text_payload}")
                            except:
                                pass
                    except:
                        pass
                            
            # UDP Layer Analysis
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                print(f"\n[UDP Layer]")
                print(f"Source Port: {udp_layer.sport}")
                print(f"Destination Port: {udp_layer.dport}")
                print(f"Length: {udp_layer.len}")
                
                # Show payload if available
                if hasattr(udp_layer, 'payload') and udp_layer.payload:
                    try:
                        payload = bytes(udp_layer.payload)
                        if len(payload) > 0:
                            print(f"\nPayload (first 100 bytes):")
                            print(payload[:100])
                    except:
                        pass
                        
            # ICMP Layer Analysis
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                print(f"\n[ICMP Layer]")
                print(f"Type: {icmp_layer.type}")
                print(f"Code: {icmp_layer.code}")
                
                type_desc = {
                    0: "Echo Reply",
                    8: "Echo Request",
                    3: "Destination Unreachable",
                    11: "Time Exceeded"
                }
                print(f"ICMP Type Description: {type_desc.get(icmp_layer.type, 'Unknown')}")
                
            # ARP Layer Analysis
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                print(f"\n[ARP Layer]")
                op_map = {1: "Request", 2: "Reply"}
                print(f"Operation: {op_map.get(arp_layer.op, arp_layer.op)}")
                print(f"Source MAC: {arp_layer.hwsrc}")
                print(f"Destination MAC: {arp_layer.hwdst}")
                print(f"Source IP: {arp_layer.psrc}")
                print(f"Destination IP: {arp_layer.pdst}")
                
            # Ethernet Layer
            if packet.haslayer(Ether):
                ether_layer = packet[Ether]
                print(f"\n[Ethernet Layer]")
                print(f"Source MAC: {ether_layer.src}")
                print(f"Destination MAC: {ether_layer.dst}")
                print(f"Ethernet Type: {hex(ether_layer.type)}")
                
        else:
            # For non-IP packets like ARP
            print(f"Non-IP packet captured")
            if packet.haslayer(Ether):
                ether_layer = packet[Ether]
                print(f"[Ethernet Layer]")
                print(f"Source MAC: {ether_layer.src}")
                print(f"Destination MAC: {ether_layer.dst}")
                print(f"Ethernet Type: {hex(ether_layer.type)}")
            print(f"Packet summary: {packet.summary()}")
    
    def start_sniffing(self, interface=None, packet_count=None, filter_str=None):
        """Start capturing packets"""
        print("\n" + "="*80)
        print("BASIC NETWORK SNIFFER - By DAani Sam")
        print("="*80)
        
        # Check for administrative privileges
        if platform.system() != 'Windows':
            if os.geteuid() != 0:
                print("WARNING: You're not running as root. Some packets may not be captured.")
                print("For full functionality, run with: sudo python3 sniffer.py")
                print()
        
        print(f"Starting packet capture...")
        print(f"Operating System: {platform.system()}")
        print(f"Interface: {interface if interface else 'Default'}")
        print(f"Filter: {filter_str if filter_str else 'None (all packets)'}")
        print(f"Packet limit: {packet_count if packet_count else 'Unlimited'}")
        print("-"*80)
        print("Press Ctrl+C to stop capture\n")
        
        self.start_time = time.time()
        
        try:
            # Start sniffing with error handling
            sniff_args = {
                'prn': self.packet_handler,
                'store': False
            }
            
            if interface:
                sniff_args['iface'] = interface
            if packet_count:
                sniff_args['count'] = packet_count
            if filter_str:
                sniff_args['filter'] = filter_str
            
            sniff(**sniff_args)
            
        except KeyboardInterrupt:
            self.stop_sniffing()
        except PermissionError as e:
            print(f"\nPermission Error: {e}")
            print("\nSolutions:")
            if platform.system() == 'Windows':
                print("1. Run Command Prompt or PowerShell as Administrator")
                print("2. Make sure Npcap or WinPcap is installed")
                print("3. Try: pip install --upgrade scapy")
            else:
                print("1. Run with: sudo python3 sniffer.py")
                print("2. Or: sudo -E python3 sniffer.py")
            sys.exit(1)
        except Exception as e:
            print(f"\nError: {e}")
            print("\nTroubleshooting tips:")
            print("1. Install Npcap/WinPcap (Windows) or libpcap (Linux/macOS)")
            print("2. Install scapy: pip install scapy")
            print("3. Check firewall settings")
            print("4. Try using: python3 -m pip install --upgrade scapy")
            sys.exit(1)
    
    def stop_sniffing(self):
        """Stop capturing and show statistics"""
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            print("\n" + "="*80)
            print("CAPTURE STOPPED")
            print("="*80)
            print(f"Total packets captured: {self.packet_count}")
            print(f"Capture duration: {elapsed_time:.2f} seconds")
            if elapsed_time > 0 and self.packet_count > 0:
                print(f"Average packets/second: {self.packet_count/elapsed_time:.2f}")
        else:
            print("\nCapture stopped. No packets captured.")
        print("="*80)

def show_available_interfaces():
    """Show available network interfaces"""
    try:
        from scapy.all import get_windows_if_list, get_if_list
        
        print("\nAvailable Network Interfaces:")
        print("-" * 50)
        
        if platform.system() == 'Windows':
            interfaces = get_windows_if_list()
            for iface in interfaces:
                name = iface.get('name', 'Unknown')
                desc = iface.get('description', '')
                ips = iface.get('ips', [])
                print(f"• {name}")
                if desc:
                    print(f"  Description: {desc}")
                if ips:
                    print(f"  IPs: {', '.join(ips)}")
                print()
        else:
            interfaces = get_if_list()
            for iface in interfaces:
                print(f"• {iface}")
    except:
        print("Unable to list interfaces automatically.")
        print("Common interface names:")
        if platform.system() == 'Windows':
            print("- Ethernet, Wi-Fi, Local Area Connection")
        elif platform.system() == 'Darwin':  # macOS
            print("- en0, en1, lo0")
        else:  # Linux
            print("- eth0, wlan0, lo")

def main():
    """Main function with menu interface"""
    sniffer = NetworkSniffer()
    
    print("\n" + "="*80)
    print("BASIC NETWORK SNIFFER - By DAani Sam")
    print("CodeAlpha Cyber Security Internship - Task 1")
    print("="*80)
    
    while True:
        print("\nSelect capture mode:")
        print("1. Capture all packets (default)")
        print("2. Capture limited number of packets")
        print("3. Capture with filter (e.g., 'tcp', 'udp', 'icmp')")
        print("4. Capture on specific interface")
        print("5. Show available interfaces")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            sniffer.start_sniffing()
            break
        elif choice == '2':
            try:
                count = int(input("Enter number of packets to capture: "))
                sniffer.start_sniffing(packet_count=count)
                break
            except ValueError:
                print("Invalid input. Please enter a number.")
        elif choice == '3':
            filter_str = input("Enter filter (e.g., 'tcp', 'udp', 'icmp', 'port 80'): ")
            count_input = input("Enter packet limit (press Enter for unlimited): ")
            if count_input:
                try:
                    sniffer.start_sniffing(packet_count=int(count_input), filter_str=filter_str)
                    break
                except ValueError:
                    print("Invalid number. Using unlimited capture.")
                    sniffer.start_sniffing(filter_str=filter_str)
                    break
            else:
                sniffer.start_sniffing(filter_str=filter_str)
                break
        elif choice == '4':
            print("\nEnter interface name (examples):")
            if platform.system() == 'Windows':
                print("- Ethernet, Wi-Fi, 'Local Area Connection'")
            elif platform.system() == 'Darwin':
                print("- en0, en1, lo0")
            else:
                print("- eth0, wlan0, lo")
            interface = input("Interface: ")
            sniffer.start_sniffing(interface=interface)
            break
        elif choice == '5':
            show_available_interfaces()
        elif choice == '6':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please select 1-6.")

if __name__ == "__main__":
    main()
