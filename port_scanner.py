"""
Port Scanner
Scans ports on a target host to check for open services
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


def scan_port(host, port, timeout=1):
    """
    Scan a single port on a host.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds
        
    Returns:
        tuple: (port, status) where status is 'open' or 'closed'
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return (port, 'open')
        else:
            return (port, 'closed')
    except socket.gaierror:
        return (port, 'error')
    except Exception as e:
        return (port, f'error: {str(e)}')


def get_service_name(port):
    """
    Get common service name for a port.
    
    Args:
        port (int): Port number
        
    Returns:
        str: Service name if known, else 'unknown'
    """
    common_ports = {
        20: 'FTP Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt'
    }
    return common_ports.get(port, 'unknown')


def scan_ports(host, ports, timeout=1, max_workers=50):
    """
    Scan multiple ports on a host.
    
    Args:
        host (str): Target hostname or IP address
        ports (list): List of port numbers to scan
        timeout (float): Connection timeout in seconds
        max_workers (int): Maximum number of concurrent threads
        
    Returns:
        dict: Dictionary with open and closed ports
    """
    print(f"\nScanning {host}...")
    print(f"Ports to scan: {len(ports)}")
    print("-" * 50)
    
    open_ports = []
    closed_ports = []
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        
        for future in as_completed(future_to_port):
            port, status = future.result()
            if status == 'open':
                open_ports.append(port)
                service = get_service_name(port)
                print(f"✓ Port {port:5d} is OPEN     [{service}]")
            elif status == 'closed':
                closed_ports.append(port)
    
    elapsed_time = time.time() - start_time
    
    print("-" * 50)
    print(f"\nScan Results:")
    print(f"  Open ports: {len(open_ports)}")
    print(f"  Closed ports: {len(closed_ports)}")
    print(f"  Scan time: {elapsed_time:.2f} seconds")
    print()
    
    return {
        'open': sorted(open_ports),
        'closed': sorted(closed_ports),
        'time': elapsed_time
    }


def scan_port_range(host, start_port, end_port, timeout=1):
    """
    Scan a range of ports.
    
    Args:
        host (str): Target hostname or IP address
        start_port (int): Starting port number
        end_port (int): Ending port number
        timeout (float): Connection timeout in seconds
    """
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Ports must be between 1-65535.")
        return
    
    ports = list(range(start_port, end_port + 1))
    return scan_ports(host, ports, timeout)


def scan_common_ports(host, timeout=1):
    """
    Scan common ports.
    
    Args:
        host (str): Target hostname or IP address
        timeout (float): Connection timeout in seconds
    """
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443]
    return scan_ports(host, common_ports, timeout)


if __name__ == "__main__":
    print("Port Scanner")
    print("-" * 50)
    
    host = input("Enter target host (IP or hostname): ").strip()
    
    if not host:
        print("Error: Host cannot be empty.")
        sys.exit(1)
    
    scan_type = input("Scan type - '1' for common ports, '2' for port range: ").strip()
    
    if scan_type == '1':
        scan_common_ports(host)
    elif scan_type == '2':
        try:
            start = int(input("Enter start port: "))
            end = int(input("Enter end port: "))
            scan_port_range(host, start, end)
        except ValueError:
            print("Error: Invalid port numbers.")
    else:
        print("Invalid choice.")
