from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, PcapWriter, Ether, IP, ICMP, TCP, UDP, get_if_list
import threading
import subprocess
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)

# Global variables
pcap_writer = None
packets = []  # To store packet information for display
sniffing_active = False
tcp_count = 0
udp_count = 0

# Function to process packets
def process_packet(packet):
    global packets, pcap_writer, tcp_count, udp_count

    logging.info("Packet captured")
    packet_info = {}

    # Ethernet Frame
    if packet.haslayer(Ether):
        ether = packet[Ether]
        packet_info['ether_dst'] = ether.dst
        packet_info['ether_src'] = ether.src
        packet_info['ether_type'] = hex(ether.type)

    # IPv4 Packet
    if packet.haslayer(IP):
        ip = packet[IP]
        packet_info['ip_src'] = ip.src
        packet_info['ip_dst'] = ip.dst
        packet_info['ip_proto'] = ip.proto

        # ICMP
        if ip.proto == 1 and packet.haslayer(ICMP):
            icmp = packet[ICMP]
            packet_info['icmp_type'] = icmp.type
            packet_info['icmp_code'] = icmp.code

        # TCP
        elif ip.proto == 6 and packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info['tcp_sport'] = tcp.sport
            packet_info['tcp_dport'] = tcp.dport
            tcp_count += 1  # Increment TCP packet count

        # UDP
        elif ip.proto == 17 and packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info['udp_sport'] = udp.sport
            packet_info['udp_dport'] = udp.dport
            udp_count += 1  # Increment UDP packet count

    packets.append(packet_info)

    # Write the packet to the PCAP file
    if pcap_writer:
        pcap_writer.write(packet)
        logging.info("Packet written to capture.pcap")

# Function to start packet sniffing
def start_sniffing(interface=None):
    global sniffing_active, pcap_writer, tcp_count, udp_count
    sniffing_active = True
    packets.clear()  # Clear old packet data
    tcp_count = 0
    udp_count = 0

    # Create a pcap writer
    pcap_writer = PcapWriter("capture.pcap", append=True, sync=True)

    # Start sniffing in a separate thread
    logging.info(f"Starting sniffing on interface: {interface or 'all interfaces'}...")
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface,  # Specify the interface (or None for all)
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not sniffing_active
        )
    )
    sniff_thread.start()
    logging.info("Sniffing thread started.")

# Function to stop packet sniffing
def stop_sniffing():
    global sniffing_active
    sniffing_active = False
    logging.info("Sniffing stopped.")

# Function to open Wireshark
def open_with_wireshark(pcap_file):
    try:
        subprocess.run(["C:\\Program Files\\Wireshark\\Wireshark.exe", pcap_file])
        logging.info("Wireshark opened successfully.")
    except FileNotFoundError:
        logging.error("Wireshark not found. Ensure it is installed and in your PATH.")

# Flask app setup
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    interface = request.json.get("interface", None)  # Optionally get the interface from the request
    start_sniffing(interface=interface)
    return jsonify({'status': 'Capture started', 'interface': interface or 'all interfaces'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    stop_sniffing()
    return jsonify({'status': 'Capture stopped'})

@app.route('/get_packets', methods=['GET'])
def get_packets():
    return jsonify(packets)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'Capturing' if sniffing_active else 'Idle',
        'packet_count': len(packets),
        'tcp_count': tcp_count,
        'udp_count': udp_count,
        'interfaces': get_if_list()  # Return available network interfaces
    })

@app.route('/open_wireshark', methods=['GET'])
def open_wireshark():
    open_with_wireshark("capture.pcap")
    return jsonify({'status': 'Wireshark opened with capture.pcap file'})

if __name__ == '__main__':
    # Print available interfaces for convenience
    logging.info(f"Available network interfaces: {get_if_list()}")
    app.run(debug=True)
