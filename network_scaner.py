import argparse
import sys

import scapy.all as sc

def scan(ip):
    """ Scans the given IP range for active devices using ARP requests.
    Returns a list of dictionaries with 'ip' and 'mac' keys. """
    
    
    
    try:
        arp_req = sc.ARP(pdst=ip)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast / arp_req
        answered = sc.srp(arp_req_broadcast, timeout=2, verbose=False)[0]

        clients = []
        for _, received in answered:
            clients.append({"ip": received.psrc, "mac": received.hwsrc})
        return clients
    except Exception as e:
        print(f"Error during scanning: {e}")
        return []

def print_result(clients):
    """
    Prints the scan results in a formatted table.
    """
    print("\nIP Address\t\tMAC Address")
    print("-" * 40)
    for client in clients:
        print(f"{client['ip']:<16}\t{client['mac']}")
    print(f"\nTotal devices found: {len(clients)}")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP / IP range (e.g. 192.168.1.1/24)")
    args = parser.parse_args()

    scan_result = scan(args.target)
    if scan_result:
        print_result(scan_result)
    else:
        print("No devices found or an error occurred.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(0)