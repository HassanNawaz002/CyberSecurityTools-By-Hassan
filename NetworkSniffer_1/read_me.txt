### Network Packet Sniffer - README

#### Description:
This is a Python-based **Network Packet Sniffer** that captures network packets in real-time. It utilizes **Scapy** for packet capturing and **Tkinter** for the GUI interface. The application provides an interactive interface to start, stop, and store captured network packets in a structured format.

#### Features:
- Start and stop packet sniffing with dedicated buttons
- Display real-time packet details in a tabular format
- Store captured packets in a CSV file for analysis
- Supports Ethernet and IP layer protocols (TCP, UDP, ICMP, etc.)
- User-friendly GUI built with Tkinter

#### How It Works:
- When the **Start** button is clicked, the application begins capturing network packets on the selected Ethernet interface.
- The captured packets are displayed in a table with details such as:
  - Packet number
  - Ethernet Interface
  - Type
  - Protocol (TCP, UDP, ICMP, etc.)
  - Source IP
  - Destination IP
  - Packet Length
  - Timestamp
- Clicking the **Stop** button halts packet capturing.
- Clicking the **Store** button saves the captured packets into a CSV file for later analysis.

#### Output:
- The captured packets are dynamically displayed in a structured GUI table.
- Stored packets are saved in CSV format with a filename `packets_YYYYMMDD_HHMMSS.csv`.

#### Notes:
- Running the script with administrator privileges may be required for full access to network packets.
- Ensure an active network connection while testing.
- The application captures packets on the **Ethernet** interface by default, but this can be modified in the code if needed.

#### Author:
Hassan Nawaz

#### License:
This project is open-source and available for educational and personal use.

