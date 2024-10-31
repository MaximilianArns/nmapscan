import nmap
import os
import ipaddress
import argparse

#Funktion för att spara resultaten till en fil, 192.168.0.50
def save_results_to_file(ip_addr, scan_info, ip_status, open_ports, open_ports_keys, file_name):
    try:
        with open(file_name, 'a') as file:
            file.write(f"Scan results for IP: {ip_addr}\n")
            file.write(f"Scan Info: {scan_info}\n")
            file.write(f"IP Status: {ip_status}\n")
            file.write(f"Open Ports: {open_ports}{open_ports_keys}\n")
            file.write("-------------------------------------------------\n")
    except Exception as e:
        print(f"An error occurred while saving results to file: {e}")

#Funktion för att läsa IP-adresser från en fil
def read_ips_from_file(file_name):
    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        return lines
    else:
        print("File not found!")
        return []

#Funktion för att kontrollera ip-adress
def is_valid_ip(ip_addr):
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False 

#Funktion för att utföra nmap-skanningar
def perform_scan(scanner, ip_addr, scan_type):
    if scan_type == "syn":
        scanner.scan(ip_addr, "1-1024", "-v -sS")
    elif scan_type == "UDP":
        scanner.scan(ip_addr, "1-1024", "-v -sU")
    elif scan_type == "Compre":
        scanner.scan(ip_addr, "1-1024", "-v -sS -sV -sC -A -O")
    else:
        return None
    return scanner[ip_addr]

scanner = nmap.PortScanner()

parser = argparse.ArgumentParser(description="This is a nmap tool")
parser.add_argument("--mode", choices=["single_ip", "scan_file"], help="Chose IP addresse(s) to scan")
parser.add_argument("--scan_type", choices=["syn", "UDP", "Compre"], help="Chose which type of scan you want to do")
parser.add_argument("--ip_addr", help="Enter the IP address you want to scan")
parser.add_argument("--file_name", help="Enter the name of the file with the IP addresses")

args = parser.parse_args()

#Alternativ 1
if args.mode == "single_ip":
    if not args.ip_addr:
        parser.error("You need to enter the IP address you want to scan")
    
    if not is_valid_ip(args.ip_addr):
        print("Invalid IP address. Please try again")


    try:
        result = perform_scan(scanner, args.ip_addr, args.scan_type)
        if not result:
            print("Invalid scan type or scan returned no results. Please try again.")
        if result:
            scan_info = scanner.scaninfo()
            ip_status =result.state()
            open_ports = result.all_protocols()
            open_ports_keys = result['tcp'].keys() if 'tcp' in result else []

            print(scan_info)
            print("IP Status:", ip_status)
            print("Open Ports:", open_ports, open_ports_keys)
            save_results_to_file(args.ip_addr, scan_info, ip_status, open_ports, open_ports_keys, "scan_results.txt")
    except Exception as e:
        print(f"An error occurred during the scan: {e}")

#Alternativ 2
elif args.mode == "scan_file":
    
    try:
        ip_addresses = read_ips_from_file(args.file_name)
        print(f"Read IP Addresses: {ip_addresses}")  #Debug output
    except FileNotFoundError:
        print("The specified file was not found. Please try again.")


    for ip_addr in ip_addresses:
        try:
            result = perform_scan(scanner, ip_addr, args.scan_type)
            if result is None:
                print(f"Invalid scan type for {ip_addr}. Skipping scan.")
                continue
            if result:
                scan_info = scanner.scaninfo()
                ip_status = result.state()
                open_ports = result.all_protocols()
                open_ports_keys = result['udp'].keys() if 'udp' in result else []

                print(scan_info)
                print("IP Status:", ip_status)
                print("Open Ports:", open_ports, open_ports_keys)
                save_results_to_file(ip_addr, scan_info, ip_status, open_ports, open_ports_keys, "scan_results.txt")

        except Exception as e:
            print(f"An error occurred while scanning {ip_addr}: {e}")