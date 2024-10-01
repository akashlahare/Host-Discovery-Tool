import os
import platform
import subprocess
import threading
import ipaddress
import time

# Function to ping a single IP address
def ping_host(ip):
    # Determine ping command based on OS
    param = "-n" if platform.system().lower() == "windows" else "-c"
    
    start_time = time.time()
    # Run ping command
    result = subprocess.run(["ping", param, "1", str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end_time = time.time()
    
    # If the ping is successful, display response time
    if result.returncode == 0:
        response_time = round((end_time - start_time) * 1000, 2)
        print(f"Host {ip} is reachable, Response Time: {response_time} ms")
    else:
        print(f"Host {ip} is unreachable")

# Function to create threads and ping all IPs in the list
def ping_ip_range(start_ip, end_ip):
    start_ip = ipaddress.IPv4Address(start_ip)
    end_ip = ipaddress.IPv4Address(end_ip)
    
    # Create threads for each IP in the range
    threads = []
    for ip in range(int(start_ip), int(end_ip) + 1):
        thread = threading.Thread(target=ping_host, args=(ipaddress.IPv4Address(ip),))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

# Main function
if __name__ == "__main__":
    # Input for start and end IP
    start_ip = input("Enter the start IP address: ")
    end_ip = input("Enter the end IP address: ")

    print(f"Pinging IP range from {start_ip} to {end_ip}...")

    # Ping IP range
    ping_ip_range(start_ip, end_ip)
