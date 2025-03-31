import socket
import psutil
import time
import datetime
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter import filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.all import conf
import pandas as pd
import os
import json

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Monitor")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        
        # Initialize network monitor
        self.monitor = NetworkMonitor(callback=self.update_stats_display)
        
        # Initialize packet sniffer
        self.packet_sniffer = PacketSniffer(callback=self.update_packet_display)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.bandwidth_tab = ttk.Frame(self.notebook)
        self.packets_tab = ttk.Frame(self.notebook)
        self.website_tab = ttk.Frame(self.notebook)
        self.connections_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.bandwidth_tab, text="Bandwidth")
        self.notebook.add(self.packets_tab, text="Packet Capture")
        self.notebook.add(self.website_tab, text="Website Tracking")
        self.notebook.add(self.connections_tab, text="Connections")
        
        # Setup the GUI components
        self.setup_bandwidth_tab()
        self.setup_packets_tab()
        self.setup_website_tab()
        self.setup_connections_tab()
        
        # Start monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_network)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Initialize connection tracking
        self.connections = {}
        self.websites_visited = {}
        
        # Set up closing handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_bandwidth_tab(self):
        # Create a frame for controls
        control_frame = ttk.Frame(self.bandwidth_tab, padding=10)
        control_frame.pack(fill=tk.X)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.interface_var = tk.StringVar(value=self.monitor.interface)
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=15)
        self.interface_combo['values'] = list(self.monitor.interfaces.keys())
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.interface_combo.bind('<<ComboboxSelected>>', self.change_interface)
        
        # Refresh button
        ttk.Button(control_frame, text="Refresh Interfaces", command=self.refresh_interfaces).pack(side=tk.LEFT, padx=5)
        
        # Pause/Resume button
        self.pause_var = tk.StringVar(value="Pause")
        self.pause_button = ttk.Button(control_frame, textvariable=self.pause_var, command=self.toggle_pause)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        # Stats display
        stats_frame = ttk.LabelFrame(self.bandwidth_tab, text="Current Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # IP address display
        ip_frame = ttk.Frame(stats_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="IP Addresses:").pack(side=tk.LEFT, padx=5)
        self.ip_var = tk.StringVar(value="Loading...")
        ttk.Label(ip_frame, textvariable=self.ip_var).pack(side=tk.LEFT, padx=5)
        
        # Download/Upload display
        speed_frame = ttk.Frame(stats_frame)
        speed_frame.pack(fill=tk.X, pady=5)
        
        # Download speed
        ttk.Label(speed_frame, text="Download:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.download_var = tk.StringVar(value="0.00 KB/s")
        ttk.Label(speed_frame, textvariable=self.download_var).grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Upload speed
        ttk.Label(speed_frame, text="Upload:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.upload_var = tk.StringVar(value="0.00 KB/s")
        ttk.Label(speed_frame, textvariable=self.upload_var).grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Total data transferred
        ttk.Label(speed_frame, text="Total Downloaded:").grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        self.total_download_var = tk.StringVar(value="0.00 KB")
        ttk.Label(speed_frame, textvariable=self.total_download_var).grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        
        ttk.Label(speed_frame, text="Total Uploaded:").grid(row=1, column=2, padx=5, pady=2, sticky=tk.W)
        self.total_upload_var = tk.StringVar(value="0.00 KB")
        ttk.Label(speed_frame, textvariable=self.total_upload_var).grid(row=1, column=3, padx=5, pady=2, sticky=tk.W)
        
        # Graph frame
        graph_frame = ttk.LabelFrame(self.bandwidth_tab, text="Network Traffic", padding=10)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Setup matplotlib figure
        self.fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.download_subplot = self.fig.add_subplot(211)
        self.upload_subplot = self.fig.add_subplot(212)
        
        # Add figure to tkinter canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update IP display
        self.update_ip_display()
    
    def setup_packets_tab(self):
        # Packet capture controls
        control_frame = ttk.Frame(self.packets_tab, padding=10)
        control_frame.pack(fill=tk.X)
        
        # Start/Stop capture button
        self.capture_var = tk.StringVar(value="Start Capture")
        self.capture_button = ttk.Button(control_frame, textvariable=self.capture_var, command=self.toggle_capture)
        self.capture_button.pack(side=tk.LEFT, padx=5)
        
        # Filter entry
        ttk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 5))
        self.filter_var = tk.StringVar(value="")
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Apply filter button
        self.apply_filter_button = ttk.Button(control_frame, text="Apply Filter", command=self.apply_filter)
        self.apply_filter_button.pack(side=tk.LEFT, padx=5)
        
        # Save captured packets button
        self.save_button = ttk.Button(control_frame, text="Save Packets", command=self.save_packets)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Clear captured packets button
        self.clear_button = ttk.Button(control_frame, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Packet list
        packet_frame = ttk.LabelFrame(self.packets_tab, text="Captured Packets", padding=10)
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create packet treeview
        self.packet_tree = ttk.Treeview(packet_frame, columns=("time", "source", "destination", "protocol", "length", "info"), show="headings")
        self.packet_tree.heading("time", text="Time")
        self.packet_tree.heading("source", text="Source")
        self.packet_tree.heading("destination", text="Destination")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("length", text="Length")
        self.packet_tree.heading("info", text="Info")
        
        self.packet_tree.column("time", width=80)
        self.packet_tree.column("source", width=130)
        self.packet_tree.column("destination", width=130)
        self.packet_tree.column("protocol", width=80)
        self.packet_tree.column("length", width=70)
        self.packet_tree.column("info", width=200)
        
        # Add scrollbar to packet tree
        packet_scroll = ttk.Scrollbar(packet_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
        packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind event to show packet details
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        
        # Packet details frame
        details_frame = ttk.LabelFrame(self.packets_tab, text="Packet Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Packet details text area
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=8)
        self.packet_details.pack(fill=tk.BOTH, expand=True)
    
    def setup_website_tab(self):
        # Website tracking controls
        control_frame = ttk.Frame(self.website_tab, padding=10)
        control_frame.pack(fill=tk.X)
        
        # Enable/Disable website tracking
        self.website_tracking_var = tk.BooleanVar(value=False)
        self.website_tracking_check = ttk.Checkbutton(
            control_frame, 
            text="Enable Website Tracking", 
            variable=self.website_tracking_var,
            command=self.toggle_website_tracking
        )
        self.website_tracking_check.pack(side=tk.LEFT, padx=5)
        
        # Clear website history button
        self.clear_websites_button = ttk.Button(control_frame, text="Clear History", command=self.clear_website_history)
        self.clear_websites_button.pack(side=tk.LEFT, padx=5)
        
        # Export website history button
        self.export_websites_button = ttk.Button(control_frame, text="Export History", command=self.export_website_history)
        self.export_websites_button.pack(side=tk.LEFT, padx=5)
        
        # Website list
        website_frame = ttk.LabelFrame(self.website_tab, text="Websites Visited", padding=10)
        website_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create website treeview
        self.website_tree = ttk.Treeview(website_frame, columns=("time", "domain", "url", "method", "status"), show="headings")
        self.website_tree.heading("time", text="Time")
        self.website_tree.heading("domain", text="Domain")
        self.website_tree.heading("url", text="URL")
        self.website_tree.heading("method", text="Method")
        self.website_tree.heading("status", text="Status")
        
        self.website_tree.column("time", width=80)
        self.website_tree.column("domain", width=150)
        self.website_tree.column("url", width=300)
        self.website_tree.column("method", width=70)
        self.website_tree.column("status", width=70)
        
        # Add scrollbar to website tree
        website_scroll = ttk.Scrollbar(website_frame, orient="vertical", command=self.website_tree.yview)
        self.website_tree.configure(yscrollcommand=website_scroll.set)
        
        website_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.website_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Website details frame
        details_frame = ttk.LabelFrame(self.website_tab, text="HTTP Request Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Website details text area
        self.website_details = scrolledtext.ScrolledText(details_frame, height=8)
        self.website_details.pack(fill=tk.BOTH, expand=True)
        
        # Bind event to show website details
        self.website_tree.bind("<Double-1>", self.show_website_details)
    
    def setup_connections_tab(self):
        # Connection tracking controls
        control_frame = ttk.Frame(self.connections_tab, padding=10)
        control_frame.pack(fill=tk.X)
        
        # Enable/Disable connection tracking
        self.connection_tracking_var = tk.BooleanVar(value=False)
        self.connection_tracking_check = ttk.Checkbutton(
            control_frame, 
            text="Enable Connection Tracking", 
            variable=self.connection_tracking_var,
            command=self.toggle_connection_tracking
        )
        self.connection_tracking_check.pack(side=tk.LEFT, padx=5)
        
        # Refresh connections button
        self.refresh_connections_button = ttk.Button(control_frame, text="Refresh", command=self.refresh_connections)
        self.refresh_connections_button.pack(side=tk.LEFT, padx=5)
        
        # Export connections button
        self.export_connections_button = ttk.Button(control_frame, text="Export", command=self.export_connections)
        self.export_connections_button.pack(side=tk.LEFT, padx=5)
        
        # Connection list
        connection_frame = ttk.LabelFrame(self.connections_tab, text="Active Connections", padding=10)
        connection_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create connection treeview
        self.connection_tree = ttk.Treeview(
            connection_frame, 
            columns=("proto", "local_addr", "remote_addr", "status", "pid", "process"), 
            show="headings"
        )
        self.connection_tree.heading("proto", text="Protocol")
        self.connection_tree.heading("local_addr", text="Local Address")
        self.connection_tree.heading("remote_addr", text="Remote Address")
        self.connection_tree.heading("status", text="Status")
        self.connection_tree.heading("pid", text="PID")
        self.connection_tree.heading("process", text="Process")
        
        self.connection_tree.column("proto", width=70)
        self.connection_tree.column("local_addr", width=150)
        self.connection_tree.column("remote_addr", width=150)
        self.connection_tree.column("status", width=100)
        self.connection_tree.column("pid", width=70)
        self.connection_tree.column("process", width=150)
        
        # Add scrollbar to connection tree
        connection_scroll = ttk.Scrollbar(connection_frame, orient="vertical", command=self.connection_tree.yview)
        self.connection_tree.configure(yscrollcommand=connection_scroll.set)
        
        connection_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.connection_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Connection details frame
        details_frame = ttk.LabelFrame(self.connections_tab, text="Connection Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Connection details text area
        self.connection_details = scrolledtext.ScrolledText(details_frame, height=8)
        self.connection_details.pack(fill=tk.BOTH, expand=True)
        
        # Bind event to show connection details
        self.connection_tree.bind("<Double-1>", self.show_connection_details)
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        self.monitor.interfaces = self.monitor.get_interfaces()
        self.interface_combo['values'] = list(self.monitor.interfaces.keys())
        
        # If current interface isn't in the list anymore, select a new one
        if self.monitor.interface not in self.monitor.interfaces:
            self.monitor.interface = self.monitor.get_default_interface()
            self.interface_var.set(self.monitor.interface)
        
        self.update_ip_display()
    
    def change_interface(self, event=None):
        """Handle interface change from dropdown"""
        new_interface = self.interface_var.get()
        if new_interface != self.monitor.interface:
            self.monitor.change_interface(new_interface)
            self.update_ip_display()
            
            # Update packet sniffer interface
            if hasattr(self, 'packet_sniffer') and self.packet_sniffer.running:
                self.toggle_capture()  # Stop current capture
                self.packet_sniffer.interface = new_interface
                self.toggle_capture()  # Restart on new interface
    
    def update_ip_display(self):
        """Update the IP address display for the selected interface"""
        if self.monitor.interface in self.monitor.interfaces:
            addresses = []
            for addr in self.monitor.interfaces[self.monitor.interface]:
                if addr['family'] in ['IPv4', 'IPv6']:
                    addresses.append(f"{addr['family']}: {addr['address']}")
            
            if addresses:
                self.ip_var.set(", ".join(addresses))
            else:
                self.ip_var.set("No IP address found")
        else:
            self.ip_var.set("Interface not available")
    
    def update_stats_display(self, download, upload, total_down, total_up):
        """Update the stats displayed in the GUI"""
        self.download_var.set(f"{download:.2f} KB/s")
        self.upload_var.set(f"{upload:.2f} KB/s")
        
        # Update total data transferred
        if total_down < 1024:
            self.total_download_var.set(f"{total_down:.2f} KB")
        elif total_down < 1024*1024:
            self.total_download_var.set(f"{total_down/1024:.2f} MB")
        else:
            self.total_download_var.set(f"{total_down/(1024*1024):.2f} GB")
            
        if total_up < 1024:
            self.total_upload_var.set(f"{total_up:.2f} KB")
        elif total_up < 1024*1024:
            self.total_upload_var.set(f"{total_up/1024:.2f} MB")
        else:
            self.total_upload_var.set(f"{total_up/(1024*1024):.2f} GB")
        
        # Update the graph if we have data
        if self.monitor.timestamp_history:
            self.update_graph()
    
    def update_graph(self):
        """Update the network traffic graph"""
        # Clear previous plots
        self.download_subplot.clear()
        self.upload_subplot.clear()
        
        # Get data
        timestamps = list(self.monitor.timestamp_history)
        downloads = list(self.monitor.download_history)
        uploads = list(self.monitor.upload_history)
        
        # Plot download speeds
        self.download_subplot.plot(range(len(timestamps)), downloads, 'b-')
        self.download_subplot.set_title(f'Download Speed ({self.monitor.interface})')
        self.download_subplot.set_ylabel('KB/s')
        self.download_subplot.grid(True)
        
        # Only show some x labels to avoid crowding
        if len(timestamps) > 10:
            indices = list(range(0, len(timestamps), len(timestamps) // 5))
            self.download_subplot.set_xticks(indices)
            self.download_subplot.set_xticklabels([timestamps[i] for i in indices], rotation=45)
        else:
            self.download_subplot.set_xticks(range(len(timestamps)))
            self.download_subplot.set_xticklabels(timestamps, rotation=45)
        
        # Plot upload speeds
        self.upload_subplot.plot(range(len(timestamps)), uploads, 'r-')
        self.upload_subplot.set_title(f'Upload Speed ({self.monitor.interface})')
        self.upload_subplot.set_ylabel('KB/s')
        self.upload_subplot.set_xlabel('Time')
        self.upload_subplot.grid(True)
        
        # Only show some x labels to avoid crowding
        if len(timestamps) > 10:
            indices = list(range(0, len(timestamps), len(timestamps) // 5))
            self.upload_subplot.set_xticks(indices)
            self.upload_subplot.set_xticklabels([timestamps[i] for i in indices], rotation=45)
        else:
            self.upload_subplot.set_xticks(range(len(timestamps)))
            self.upload_subplot.set_xticklabels(timestamps, rotation=45)
        
        # Update the figure
        self.fig.tight_layout()
        self.canvas.draw()
    
    def toggle_pause(self):
        """Pause or resume monitoring"""
        if self.monitor.paused:
            self.monitor.paused = False
            self.pause_var.set("Pause")
        else:
            self.monitor.paused = True
            self.pause_var.set("Resume")
    
    def toggle_capture(self):
        """Start or stop packet capture"""
        if not hasattr(self.packet_sniffer, 'running') or not self.packet_sniffer.running:
            # Start capturing
            self.packet_sniffer.interface = self.monitor.interface
            self.packet_sniffer.start_capture()
            self.capture_var.set("Stop Capture")
        else:
            # Stop capturing
            self.packet_sniffer.stop_capture()
            self.capture_var.set("Start Capture")
    
    def apply_filter(self):
        """Apply filter to packet capture"""
        filter_text = self.filter_var.get()
        self.packet_sniffer.set_filter(filter_text)
        
        # Update packet list with filtered packets
        self.clear_packet_tree()
        for packet in self.packet_sniffer.get_filtered_packets():
            self.add_packet_to_tree(packet)
    
    def save_packets(self):
        """Save captured packets to file"""
        if not self.packet_sniffer.packets:
            messagebox.showinfo("No Packets", "No packets to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                scapy.wrpcap(filename, self.packet_sniffer.packets)
                messagebox.showinfo("Success", f"Saved {len(self.packet_sniffer.packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets: {e}")
    
    def clear_packets(self):
        """Clear captured packets"""
        self.packet_sniffer.clear_packets()
        self.clear_packet_tree()
        self.packet_details.delete(1.0, tk.END)
    
    def clear_packet_tree(self):
        """Clear packet tree view"""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
    
    def add_packet_to_tree(self, packet):
        """Add a packet to the tree view"""
        # Extract basic info from packet
        try:
            time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                
                # Determine protocol name
                if packet.haslayer(scapy.TCP):
                    proto_name = "TCP"
                    sport = packet[scapy.TCP].sport
                    dport = packet[scapy.TCP].dport
                    info = f"{sport} → {dport}"
                    
                    # Check for HTTP
                    if sport == 80 or dport == 80 or sport == 443 or dport == 443:
                        proto_name = "HTTP(S)"
                elif packet.haslayer(scapy.UDP):
                    proto_name = "UDP"
                    sport = packet[scapy.UDP].sport
                    dport = packet[scapy.UDP].dport
                    info = f"{sport} → {dport}"
                elif packet.haslayer(scapy.ICMP):
                    proto_name = "ICMP"
                    icmp_type = packet[scapy.ICMP].type
                    info = f"Type: {icmp_type}"
                else:
                    proto_name = f"IP/{proto}"
                    info = ""
            elif packet.haslayer(scapy.ARP):
                src = packet[scapy.ARP].psrc
                dst = packet[scapy.ARP].pdst
                proto_name = "ARP"
                info = "Who has" if packet[scapy.ARP].op == 1 else "is at"
            else:
                src = "Unknown"
                dst = "Unknown"
                proto_name = packet.name
                info = ""
                
            # Get packet length
            length = len(packet)
            
            # Add to tree
            self.packet_tree.insert("", "end", values=(time_str, src, dst, proto_name, length, info))
            
            # Store in website tracking if HTTP or HTTPS
            if self.website_tracking_var.get() and proto_name == "HTTP(S)":
                # Check if it's HTTP Request
                if packet.haslayer(HTTPRequest):
                    self.process_http_request(packet, time_str)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def update_packet_display(self, packet):
        """Callback for new packets"""
        self.add_packet_to_tree(packet)
        
        # Update the connections tab if enabled
        if self.connection_tracking_var.get():
            self.refresh_connections()
    
    def show_packet_details(self, event):
        """Show details for selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        idx = self.packet_tree.index(item)
        
        if idx < len(self.packet_sniffer.packets):
            packet = self.packet_sniffer.packets[idx]
            self.packet_details.delete(1.0, tk.END)
            
            # Format packet details
            details = []
            details.append(f"Packet {idx + 1} Details:")
            details.append("-" * 50)
            
            # Add timestamp
            time_str = self.packet_tree.item(item, "values")[0]
            details.append(f"Time: {time_str}")
            
            # Layer details
            for i, layer in enumerate(packet.layers()):
                details.append(f"\nLayer {i + 1}: {layer.__name__}")
                details.append("-" * 30)
                
                # Get fields for this layer
                if hasattr(packet, 'getlayer') and packet.getlayer(layer) is not None:
                    layer_obj = packet.getlayer(layer)
                    if hasattr(layer_obj, 'fields'):
                        for field, value in layer_obj.fields.items():
                            details.append(f"{field}: {value}")
            
            # Add raw bytes
            details.append("\nRaw Bytes (hex):")
            details.append("-" * 30)
            hex_bytes = ' '.join(f"{b:02x}" for b in bytes(packet))
            # Limit to 200 bytes to avoid very long displays
            if len(hex_bytes) > 600:
                hex_bytes = hex_bytes[:600] + "..."
            details.append(hex_bytes)
            
            # Insert into details view
            self.packet_details.insert(tk.END, "\n".join(details))
    
    def toggle_website_tracking(self):
        """Enable or disable website tracking"""
        if self.website_tracking_var.get():
            # If packet capture is not running, start it
            if not hasattr(self.packet_sniffer, 'running') or not self.packet_sniffer.running:
                self.toggle_capture()
        else:
            # No need to stop packet capture, just won't process HTTP
            pass
    
    def process_http_request(self, packet, time_str):
        """Process HTTP request packet for website tracking"""
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                ip_layer = packet[scapy.IP]
                
                # Extract HTTP info
                host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ""
                path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else ""
                method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else ""
                
                # Full URL
                url = f"http://{host}{path}"
                
                # Source and destination
                src = ip_layer.src
                dst = ip_layer.dst
                
                # Add to websites list
                website_id = len(self.websites_visited) + 1
                self.websites_visited[website_id] = {
                    'time': time_str,
                    'host': host,
                    'url': url,
                    'method': method,
                    'src': src,
                    'dst': dst,
                    'headers': {k.decode(): v.decode() for k, v in http_layer.fields.items() 
                               if isinstance(k, bytes) and isinstance(v, bytes)}
                }
                
                # Add to tree view
                self.website_tree.insert("", "end", values=(time_str, host, url, method, ""))
                
        except Exception as e:
            print(f"Error processing HTTP packet: {e}")
    
    def clear_website_history(self):
        """Clear website tracking history"""
        self.websites_visited = {}
        for item in self.website_tree.get_children():
            self.website_tree.delete(item)
        self.website_details.delete(1.0, tk.END)
    
    def export_website_history(self):
        """Export website tracking history to CSV"""
        if not self.websites_visited:
            messagebox.showinfo("No Data", "No website tracking data to export.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                # Create dataframe from website history
                data = []
                for site_id, site_info in self.websites_visited.items():
                    data.append({
                        'Time': site_info['time'],
                        'Host': site_info['host'],
                        'URL': site_info['url'],
                        'Method': site_info['method'],
                        'Source IP': site_info['src'],
                        'Destination IP': site_info['dst']
                    })
                
                df = pd.DataFrame(data)
                df.to_csv(filename, index=False)
                messagebox.showinfo("Success", f"Exported {len(data)} records to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {e}")
    
    def show_website_details(self, event):
        """Show details for selected website"""
        selection = self.website_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        idx = self.website_tree.index(item)
        
        if idx < len(self.websites_visited):
            site_info = self.websites_visited[idx + 1]  # +1 because IDs start at 1
            
            self.website_details.delete(1.0, tk.END)
            
            # Format website details
            details = []
            details.append(f"HTTP Request Details:")
            details.append("-" * 50)
            details.append(f"Time: {site_info['time']}")
            details.append(f"Host: {site_info['host']}")
            details.append(f"URL: {site_info['url']}")
            details.append(f"Method: {site_info['method']}")
            details.append(f"Source IP: {site_info['src']}")
            details.append(f"Destination IP: {site_info['dst']}")
            
            # Headers
            if 'headers' in site_info and site_info['headers']:
                details.append("\nHeaders:")
                for header, value in site_info['headers'].items():
                    details.append(f"  {header}: {value}")
            
            # Insert into details view
            self.website_details.insert(tk.END, "\n".join(details))
    
    def toggle_connection_tracking(self):
        """Enable or disable connection tracking"""
        if self.connection_tracking_var.get():
            self.refresh_connections()
    
    def refresh_connections(self):
        """Refresh the connections list"""
        # Clear existing items
        for item in self.connection_tree.get_children():
            self.connection_tree.delete(item)
        
        # Get all connections
        try:
            connections = psutil.net_connections(kind='all')
            self.connections = {}
            
            for idx, conn in enumerate(connections):
                # Extract connection info
                proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                
                # Local address
                if conn.laddr:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                else:
                    laddr = ""
                
                # Remote address
                if conn.raddr:
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                else:
                    raddr = ""
                
                # Process info
                pid = conn.pid if conn.pid else ""
                pname = ""
                if pid:
                    try:
                        process = psutil.Process(pid)
                        pname = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Status
                status = conn.status if hasattr(conn, 'status') else ""
                
                # Store connection
                self.connections[idx + 1] = {
                    'proto': proto,
                    'laddr': laddr,
                    'raddr': raddr,
                    'status': status,
                    'pid': pid,
                    'process': pname
                }
                
                # Add to tree
                self.connection_tree.insert("", "end", values=(proto, laddr, raddr, status, pid, pname))
                
        except (psutil.AccessDenied, PermissionError) as e:
            messagebox.showwarning("Permission Error", 
                                   "Insufficient permissions to access connection information. Try running as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh connections: {e}")
    
    def export_connections(self):
        """Export connections to CSV"""
        if not self.connections:
            messagebox.showinfo("No Data", "No connection data to export.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                # Create dataframe from connections
                data = []
                for conn_id, conn_info in self.connections.items():
                    data.append({
                        'Protocol': conn_info['proto'],
                        'Local Address': conn_info['laddr'],
                        'Remote Address': conn_info['raddr'],
                        'Status': conn_info['status'],
                        'PID': conn_info['pid'],
                        'Process': conn_info['process']
                    })
                
                df = pd.DataFrame(data)
                df.to_csv(filename, index=False)
                messagebox.showinfo("Success", f"Exported {len(data)} records to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {e}")
    
    def show_connection_details(self, event):
        """Show details for selected connection"""
        selection = self.connection_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        idx = self.connection_tree.index(item)
        
        if idx < len(self.connections):
            conn_info = self.connections[idx + 1]  # +1 because IDs start at 1
            
            self.connection_details.delete(1.0, tk.END)
            
            # Format connection details
            details = []
            details.append(f"Connection Details:")
            details.append("-" * 50)
            details.append(f"Protocol: {conn_info['proto']}")
            details.append(f"Local Address: {conn_info['laddr']}")
            details.append(f"Remote Address: {conn_info['raddr']}")
            details.append(f"Status: {conn_info['status']}")
            details.append(f"Process ID (PID): {conn_info['pid']}")
            details.append(f"Process Name: {conn_info['process']}")
            
            # Add process details if available
            if conn_info['pid']:
                try:
                    process = psutil.Process(conn_info['pid'])
                    details.append("\nProcess Details:")
                    details.append(f"  Full Path: {process.exe()}")
                    details.append(f"  Started: {datetime.datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}")
                    details.append(f"  Status: {process.status()}")
                    details.append(f"  CPU Usage: {process.cpu_percent()}%")
                    details.append(f"  Memory Usage: {process.memory_info().rss / (1024*1024):.2f} MB")
                    
                    # Get command line if possible
                    try:
                        cmdline = process.cmdline()
                        if cmdline:
                            details.append(f"  Command Line: {' '.join(cmdline)}")
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    details.append("\nProcess details not available (Process may have terminated)")
            
            # Insert into details view
            self.connection_details.insert(tk.END, "\n".join(details))
    
    def monitor_network(self):
        """Background thread for network monitoring"""
        while self.running:
            if not self.monitor.paused:
                self.monitor.update_stats()
            time.sleep(1)
    
    def on_closing(self):
        """Handle window closing"""
        self.running = False
        
        # Stop packet capture if running
        if hasattr(self, 'packet_sniffer') and hasattr(self.packet_sniffer, 'running') and self.packet_sniffer.running:
            self.packet_sniffer.stop_capture()
        
        # Wait for threads to finish
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
        
        self.root.destroy()


class NetworkMonitor:
    """Class to monitor network traffic"""
    
    def __init__(self, callback=None):
        self.interfaces = self.get_interfaces()
        self.interface = self.get_default_interface()
        self.callback = callback
        
        # Initialize counters
        self.last_received = 0
        self.last_sent = 0
        self.last_check = time.time()
        
        # Initialize history (for graphs)
        self.max_history = 60  # Keep last 60 seconds
        self.download_history = deque(maxlen=self.max_history)
        self.upload_history = deque(maxlen=self.max_history)
        self.timestamp_history = deque(maxlen=self.max_history)
        
        # Total data transferred
        self.total_download = 0
        self.total_upload = 0
        
        # Initialize paused state
        self.paused = False
        
        # Get initial stats
        self.update_stats(first_run=True)
    
    def get_interfaces(self):
        """Get all network interfaces"""
        interfaces = {}
        stats = psutil.net_if_addrs()
        for interface, addresses in stats.items():
            addresses_info = []
            for addr in addresses:
                family = 'Unknown'
                
                if addr.family == socket.AF_INET:
                    family = 'IPv4'
                elif addr.family == socket.AF_INET6:
                    family = 'IPv6'
                elif addr.family == psutil.AF_LINK:
                    family = 'MAC'
                
                addresses_info.append({
                    'family': family,
                    'address': addr.address,
                    'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                    'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                })
            
            interfaces[interface] = addresses_info
        
        return interfaces
    
    def get_default_interface(self):
        """Get the default interface"""
        # On Windows, usually the first interface that has IPv4 address
        # On Linux/Mac, usually the interface that's not loopback and has IPv4
        
        if not self.interfaces:
            return ""
        
        # First try to find a non-loopback interface with IPv4
        for interface, addresses in self.interfaces.items():
            has_ipv4 = False
            is_loopback = False
            
            for addr in addresses:
                if addr['family'] == 'IPv4':
                    has_ipv4 = True
                    if addr['address'].startswith('127.'):
                        is_loopback = True
            
            if has_ipv4 and not is_loopback:
                return interface
        
        # If no suitable interface found, return the first one
        return list(self.interfaces.keys())[0]
    
    def change_interface(self, interface):
        """Change the monitored interface"""
        if interface in self.interfaces:
            self.interface = interface
            
            # Reset counters
            self.last_received = 0
            self.last_sent = 0
            self.last_check = time.time()
            
            # Clear history
            self.download_history.clear()
            self.upload_history.clear()
            self.timestamp_history.clear()
            
            # Reset total data
            self.total_download = 0
            self.total_upload = 0
            
            # Update stats
            self.update_stats(first_run=True)
    
    def update_stats(self, first_run=False):
        """Update network stats"""
        try:
            # Get current stats
            stats = psutil.net_io_counters(pernic=True)
            
            if self.interface not in stats:
                return
            
            # Calculate speeds
            now = time.time()
            received = stats[self.interface].bytes_recv / 1024  # KB
            sent = stats[self.interface].bytes_sent / 1024  # KB
            
            if not first_run:
                time_diff = now - self.last_check
                
                # Calculate speeds in KB/s
                download_speed = (received - self.last_received) / time_diff
                upload_speed = (sent - self.last_sent) / time_diff
                
                # Update total data transferred
                self.total_download += (received - self.last_received)
                self.total_upload += (sent - self.last_sent)
                
                # Add to history
                current_time = datetime.datetime.now().strftime("%H:%M:%S")
                self.download_history.append(download_speed)
                self.upload_history.append(upload_speed)
                self.timestamp_history.append(current_time)
                
                # Call callback
                if self.callback:
                    self.callback(download_speed, upload_speed, self.total_download, self.total_upload)
            
            # Save current stats for next calculation
            self.last_received = received
            self.last_sent = sent
            self.last_check = now
            
        except Exception as e:
            print(f"Error updating network stats: {e}")


class PacketSniffer:
    """Class to capture and analyze network packets"""
    
    def __init__(self, callback=None):
        self.interface = None
        self.callback = callback
        self.running = False
        self.packets = []
        self.filter_text = ""
        self.sniffer_thread = None
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.running:
            return
        
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._capture_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
    
    def _capture_packets(self):
        """Capture packets using scapy"""
        def packet_callback(packet):
            if not self.running:
                return
            
            self.packets.append(packet)
            if self.callback:
                self.callback(packet)
        
        # Start sniffing
        try:
            scapy.sniff(
                iface=self.interface,
                prn=packet_callback,
                store=False,
                filter=self.filter_text if self.filter_text else None,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"Error in packet capture: {e}")
            self.running = False
    
    def set_filter(self, filter_text):
        """Set Berkeley Packet Filter"""
        self.filter_text = filter_text
    
    def get_filtered_packets(self):
        """Return packets filtered by current filter text"""
        if not self.filter_text:
            return self.packets
        
        # Basic implementation - a more robust solution would use real BPF filtering
        filtered_packets = []
        for packet in self.packets:
            packet_str = str(packet.summary()).lower()
            
            if self.filter_text.lower() in packet_str:
                filtered_packets.append(packet)
        
        return filtered_packets
    
    def clear_packets(self):
        """Clear captured packets"""
        self.packets = []


def main():
    root = tk.Tk()
    
    # Apply theme
    style = ttk.Style()
    try:
        # Try to use a modern theme if available
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        elif 'vista' in available_themes:
            style.theme_use('vista')
    except Exception:
        pass  # Use default theme if others not available
    
    app = NetworkMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
