#pt1 build a simple packet sniffer

#step1 import necessary modules
from scapy.all import sniff, IP, ICMP

#step2 define a callback function
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Optionally, check if it is an ICMP packet (e.g., ping)
        if packet.haslayer(ICMP):
            print("  [*] ICMP Packet detected")

#step3 capture packets
if __name__ == "__main__":
    # Start sniffing and process 10 packets (change count as needed)
    print("Starting packet capture...")
    sniff(prn=packet_callback, count=10)
    print("Packet capture complete.")

#pt2 building a simple network scanner

#step 1 import modules for scanning
from scapy.all import ARP, Ether, srp

#step2 define the network scanner function
def scan_network(ip_range):
    """
    Scans the given IP range using ARP requests.
    
    :param ip_range: String representing the target network range, e.g., "192.168.1.1/24"
    :return: A list of dictionaries containing discovered devices' IP and MAC addresses.
    """
    # Create an ARP request packet targeting the specified IP range
    arp_request = ARP(pdst=ip_range)
    
    # Create an Ethernet frame with a broadcast MAC address (ff:ff:ff:ff:ff:ff)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and the ARP request into a single packet
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and capture the response
    answered_list = srp(arp_request_broadcast, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in answered_list:
        # For each response, extract the IP and MAC addresses
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

#step3 execute the scanner and print results
if __name__ == "__main__":
    target_range = "192.168.1.0/24"  # Change this to your network's range
    print(f"Scanning network: {target_range}")
    discovered_devices = scan_network(target_range)
    
    print("Devices discovered on the network:")
    for device in discovered_devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")