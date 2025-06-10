import streamlit as st
from scapy.all import ARP, Ether, srp, sr1, IP, TCP
import socket
import ipaddress
import requests
import csv
import io

def get_local_subnet():
    """Try to detect local IP and convert to subnet (e.g. 192.168.1.0/24)"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        return str(network)
    except Exception:
        return '192.168.1.0/24'  # fallback

def lookup_mac_vendor(mac):
    """Lookup vendor from MAC address using macvendors.co API"""
    try:
        url = f'https://api.macvendors.com/{mac}'
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception:
        return "Lookup Failed"

def scan_network(subnet):
    """Perform ARP scan on the subnet"""
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_common_ports(ip):
    """Scan a few common TCP ports (80, 443, 22) on given IP"""
    common_ports = [22, 80, 443]
    open_ports = []
    for port in common_ports:
        pkt = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if pkt and pkt.haslayer(TCP) and pkt.getlayer(TCP).flags == 0x12:  # SYN-ACK
            open_ports.append(port)
    return open_ports

# UI setup
st.set_page_config(page_title="Network Scanner", page_icon="📡")

st.markdown("<h1 style='color:#ff6600;'>📡 Network Scanner</h1>", unsafe_allow_html=True)
st.write("Scan a subnet to find active devices on your local network.")

default_subnet = get_local_subnet()
subnet = st.text_input("Enter the subnet (e.g., 192.168.1.0/24):", value=default_subnet)

scan_ports = st.checkbox("Scan common TCP ports (22, 80, 443) on each device")

if st.button("Scan Network"):
    if subnet:
        st.write(f"Scanning subnet: {subnet}... This may take a moment.")
        progress = st.progress(0)

        try:
            devices = scan_network(subnet)
            progress.progress(50)

            if devices:
                # Enrich devices with vendor and optionally open ports
                for device in devices:
                    device['vendor'] = lookup_mac_vendor(device['mac'])
                    if scan_ports:
                        device['open_ports'] = scan_common_ports(device['ip'])
                    else:
                        device['open_ports'] = []

                progress.progress(90)

                st.success(f"Found {len(devices)} active device(s):")

                for device in devices:
                    st.write(f"- IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")
                    if device['open_ports']:
                        st.write(f"  Open ports: {', '.join(str(p) for p in device['open_ports'])}")
                    else:
                        st.write("  No common open ports found or port scan skipped.")

                progress.progress(100)

                # Prepare CSV download
                csv_buffer = io.StringIO()
                csv_writer = csv.writer(csv_buffer)
                csv_writer.writerow(['IP', 'MAC', 'Vendor', 'Open Ports'])
                for d in devices:
                    csv_writer.writerow([d['ip'], d['mac'], d['vendor'], ','.join(str(p) for p in d['open_ports'])])
                csv_data = csv_buffer.getvalue()
                st.download_button(label="Download scan results CSV", data=csv_data, file_name='network_scan.csv', mime='text/csv')

            else:
                st.warning("No active devices found on this subnet.")
                st.info("Try running as Administrator/root or check your subnet.")
        except Exception as e:
            st.error(f"Error scanning network: {e}")
    else:
        st.error("Please enter a valid subnet.")

st.markdown("\n🔒 Built with Streamlit and Python")
