import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
import threading
import csv
import socket
from datetime import datetime

# Global variables
sniffing = False
packets = []
packet_counter = 0
iface = "Ethernet"  # Change this based on your system

# Mapping of protocol numbers to names
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    8: "EGP",
    9: "IGP",
    41: "IPv6",
    89: "OSPF",
}

# Function to get protocol name from number
def get_protocol_name(proto_num):
    return PROTOCOLS.get(proto_num, "Unknown")

# Function to start packet sniffing
def start_sniffing():
    global sniffing, packet_counter, packets
    sniffing = True
    packet_counter = 0
    packets.clear()
    
    # Start sniffing in a separate thread
    thread = threading.Thread(target=sniff_packets, daemon=True)
    thread.start()

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False

# Function to store packets in a CSV file
def store_packets():
    if not packets:
        messagebox.showwarning("Warning", "No packets to save!")
        return

    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["No.", "Ethernet", "Type", "Protocol", "Source IP", "Dest IP", "Length", "Time"])
        writer.writerows(packets)

    messagebox.showinfo("Success", f"Packets saved to {filename}")

# Function to capture packets
def sniff_packets():
    sniff(prn=process_packet, store=False, iface=iface)

# Function to process and display packets
def process_packet(packet):
    global packet_counter
    if not sniffing:
        return
    
    if packet.haslayer("IP"):
        packet_counter += 1
        ethernet = iface
        packet_type = packet.sprintf("%Ether.type%") if packet.haslayer("Ether") else "N/A"
        protocol = get_protocol_name(packet.proto)
        source_ip = packet["IP"].src
        dest_ip = packet["IP"].dst
        length = len(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Store data in a list
        packet_data = [packet_counter, ethernet, packet_type, protocol, source_ip, dest_ip, length, timestamp]
        packets.append(packet_data)

        # Insert data into Treeview
        tree.insert("", "end", values=packet_data)

# Create main application window
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("900x400")

# Create buttons
button_frame = tk.Frame(root)
button_frame.pack(side=tk.TOP, pady=5)

start_button = tk.Button(button_frame, text="Start", command=start_sniffing, bg="green", fg="white")
start_button.grid(row=0, column=0, padx=10)

stop_button = tk.Button(button_frame, text="Stop", command=stop_sniffing, bg="red", fg="white")
stop_button.grid(row=0, column=1, padx=10)

store_button = tk.Button(button_frame, text="Store", command=store_packets, bg="blue", fg="white")
store_button.grid(row=0, column=2, padx=10)

# Create Table
columns = ("No.", "Ethernet", "Type", "Protocol", "Source IP", "Dest IP", "Length", "Time")
tree = ttk.Treeview(root, columns=columns, show="headings")

# Define column headings
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=100)

tree.pack(expand=True, fill="both")

# Run application
root.mainloop()
