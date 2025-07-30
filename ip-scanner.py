#!/usr/bin/env python3
import socket
import subprocess
import sys
from datetime import datetime
import concurrent.futures
import ipaddress

def display_banner():
    print(r"""
   ___ ____    ____                              __                 
  |_ _|  _ \  / ___|   _ _ __  ___  ___ _ __   / _| ___  __ _ _ __ 
   | || |_) | \___ \  | | '_ \/ __|/ _ \ '__| | |_ / _ \/ _` | '__|
   | ||  __/   ___) | | | | | \__ \  __/ |    |  _|  __/ (_| | |   
  |___|_|     |____/  |_|_| |_|___/\___|_|    |_|  \___|\__,_|_|   
                                                                    
  IP SCANNER by Kartikey Agnihotri
  ================================
  """)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_ip(ip, ports_to_scan):
    try:
        # Ping check first
        subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], stderr=subprocess.STDOUT)
        
        # If ping is successful, scan ports
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, ip, port) for port in ports_to_scan]
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
        
        return ip, open_ports
    except:
        return None, []

def main():
    display_banner()
    
    # Get network range to scan
    while True:
        network_input = input("Enter IP or network range to scan (e.g., 192.168.1.1 or 192.168.1.0/24): ")
        
        try:
            network = ipaddress.ip_network(network_input, strict=False)
            break
        except ValueError:
            print("Invalid IP or network range. Please try again.")
    
    # Get ports to scan
    ports_input = input("Enter ports to scan (comma separated, or 'default' for common ports): ")
    if ports_input.lower() == 'default':
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
    else:
        try:
            ports_to_scan = [int(port.strip()) for port in ports_input.split(',')]
        except:
            print("Invalid port list. Using default ports.")
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
    
    print(f"\nScanning {network.num_addresses} IPs for ports: {ports_to_scan}")
    print("Scanning started at: " + str(datetime.now()))
    print("-" * 60)
    
    active_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_ip, str(host), ports_to_scan): host for host in network.hosts()}
        
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                ip, open_ports = future.result()
                if ip:
                    active_ips.append((ip, open_ports))
                    print(f"Host {ip} is up - Open ports: {open_ports}")
            except:
                pass
    
    print("-" * 60)
    print("Scanning completed at: " + str(datetime.now()))
    print("\nSummary:")
    for ip, ports in active_ips:
        print(f"{ip}: {ports if ports else 'No open ports found'}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
