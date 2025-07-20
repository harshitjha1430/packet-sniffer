from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, PcapWriter, Ether, IP, ICMP, TCP, UDP, get_if_list
import threading
import subprocess
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)

# Flask App Setup
app = Flask(__name__)

# Global Variables
pcap_writer = None
packets = []  # Store packet information for display
sniffing_active = False
tcp_count = 0
udp_count = 0
filter_protocol = None  # Current protocol filter (e.g., 'tcp', 'udp', etc.)
current_interface = None  # Current interface for capture


# Function to process packets
def process_packet(packet):
    global packets, pcap_writer, tcp_count, udp_count, filter_protocol

    # Apply filtering logic
    if filter_protocol == "tcp" and not packet.haslayer(TCP):
        return
    elif filter_protocol == "udp" and not packet.haslayer(UDP):
        return
    elif filter_protocol == "icmp" and not packet.haslayer(ICMP):
        return

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
            tcp_count += 1

        # UDP
        elif ip.proto == 17 and packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info['udp_sport'] = udp.sport
            packet_info['udp_dport'] = udp.dport
            udp_count += 1

    packets.append(packet_info)

    # Write the packet to the PCAP file
    if pcap_writer:
        pcap_writer.write(packet)


# Function to start packet sniffing
def start_sniffing(interface=None, filter_protocol=None):
    global sniffing_active, pcap_writer, tcp_count, udp_count, current_interface

    sniffing_active = True
    packets.clear()  # Clear previous packets
    tcp_count = 0
    udp_count = 0
    current_interface = interface

    # Set the global filter protocol
    globals()['filter_protocol'] = filter_protocol

    # Create a PCAP writer
    pcap_writer = PcapWriter("capture.pcap", append=True, sync=True)

    # Start sniffing in a thread
    logging.info(f"Starting sniffing on interface: {interface or 'all interfaces'} with filter: {filter_protocol or 'None'}")
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface,  # Specify interface (or None for all)
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


# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = get_if_list()
    return jsonify({"interfaces": interfaces})


@app.route('/start_capture', methods=['POST'])
def start_capture():
    interface = request.json.get("interface", None)  # Get interface from request
    filter_protocol = request.json.get("filter_protocol", None)  # Get protocol filter
    start_sniffing(interface=interface, filter_protocol=filter_protocol)
    return jsonify({
        'status': 'Capture started',
        'interface': interface or 'all interfaces',
        'filter_protocol': filter_protocol or 'None'
    })


@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    stop_sniffing()
    return jsonify({'status': 'Capture stopped'})


@app.route('/update_filter', methods=['POST'])
def update_filter():
    global sniffing_active, filter_protocol, current_interface
    if sniffing_active:
        stop_sniffing()
        filter_protocol = request.json.get("filter_protocol", None)
        interface = request.json.get("interface", current_interface)
        start_sniffing(interface=interface, filter_protocol=filter_protocol)
        return jsonify({
            'status': 'Filter updated and capture restarted',
            'interface': interface or 'all interfaces',
            'filter_protocol': filter_protocol or 'None'
        })
    else:
        return jsonify({'status': 'No active capture to update.'})


@app.route('/reset_filters', methods=['POST'])
def reset_filters():
    global sniffing_active, filter_protocol, current_interface
    if sniffing_active:
        stop_sniffing()
        filter_protocol = None
        start_sniffing(interface=current_interface)
    return jsonify({'status': 'Filters reset and capture restarted'})


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
        'interfaces': get_if_list()
    })


@app.route('/open_wireshark', methods=['GET'])
def open_wireshark():
    try:
        subprocess.run(["C:\\Program Files\\Wireshark\\Wireshark.exe", "capture.pcap"])
        return jsonify({'status': 'Wireshark opened with capture.pcap'})
    except FileNotFoundError:
        return jsonify({'status': 'Wireshark not found. Please install or check your PATH.'})


if __name__ == '__main__':
    logging.info(f"Available network interfaces: {get_if_list()}")
    app.run(debug=True)
