import subprocess
import re
import threading
from queue import Queue
from ipaddress import ip_network
import pyfiglet
import time
import socket
import os
from colorama import Fore, Back, Style, init

def create_banner(text, font='slant'):
    figlet = pyfiglet.Figlet(font=font)
    banner = figlet.renderText(text)
    return banner

def color_banner(banner_text):
    banner_color = Fore.CYAN
    border_color = Fore.GREEN
    special_char = '★'  
    reset_color = Style.RESET_ALL


    lines = banner_text.splitlines()
    max_length = len(lines[0]) + 4
    border = border_color + (special_char * max_length) + reset_color + "\n"
    colored_banner = border + banner_color + special_char + ' ' + banner_text.replace("\n", "\n" + special_char + ' ') + ' ' + special_char + reset_color + "\n" + border

    return colored_banner

def banner():
    print(color_banner(create_banner("AlienX")))
    print(Fore.GREEN + "Advanced Network IP Scanner" + Style.RESET_ALL)
    print(Fore.GREEN + "          Developed by Sunil" + Style.RESET_ALL)
    print(Fore.GREEN + "=========================================" + Style.RESET_ALL)

def extract_network_and_host(ip):
    parts = ip.split('.')
    network = '.'.join(parts[:3]) + '.'
    host = int(parts[3])
    return network, host

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_subnet_mask():
    if os.name == 'nt':  # For Windows
        process = subprocess.Popen("ipconfig", stdout=subprocess.PIPE)
        for line in process.stdout:
            if b"Subnet Mask" in line:
                return line.split(b":")[-1].strip().decode()
    else:  # For Unix/Linux/Mac
        process = subprocess.Popen("ifconfig", stdout=subprocess.PIPE)
        for line in process.stdout:
            if b"netmask" in line:
                return line.split(b"netmask")[-1].strip().decode().split()[0]
    return None

def get_network_range():
    local_ip = get_local_ip()
    subnet_mask = get_subnet_mask()
    network = ip_network(f"{local_ip}/{subnet_mask}", strict=False)
    return str(network.network_address), str(network.broadcast_address)

def ping_host(network, host, ping_count):
    process = subprocess.getoutput(f"ping -n {ping_count} {network}{host}")
    return process

def is_host_up(response):
    return re.search(r"TTL=", response) is not None

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

def get_port_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def worker(bro, results, network, ping_count, retries, ports):
    while not bro.empty():
        host = bro.get()
        ip = f"{network}{host}"
        for _ in range(retries):
            response = ping_host(network, host, ping_count)
            if is_host_up(response):
                open_ports = scan_ports(ip, ports)
                port_names = [(port, get_port_name(port)) for port in open_ports]
                results.append((ip, "up", port_names))
                break
        else:
            results.append((ip, "down", []))
        bro.task_done()

def scan_network(bro_first_ip, bro_last_ip, ping_count, num_threads, retries, ports):
    network, bro_first_host = extract_network_and_host(bro_first_ip)
    _, bro_last_host = extract_network_and_host(bro_last_ip)

    bro = Queue()
    results = []

    for i in range(bro_first_host, bro_last_host + 1):
        bro.put(i)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(bro, results, network, ping_count, retries, ports))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return results

def main():
    init()  
    banner()
    bro_first_ip, bro_last_ip = get_network_range()
    ping_count = int(input("Enter the number of ping attempts: "))
    num_threads = int(input("Enter the number of threads: "))
    retries = int(input("Enter the number of retries: "))
    ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080]  # Common ports to scan

    print(f"Scanning IP range from {bro_first_ip} to {bro_last_ip} with {ping_count} ping attempts, {num_threads} threads, and {retries} retries...")

    start_time = time.time()
    results = scan_network(bro_first_ip, bro_last_ip, ping_count, num_threads, retries, ports)
    end_time = time.time()

    with open("scan_results.txt", "w") as file:
        for result in results:
            ip, status, open_ports = result
            print(Fore.GREEN + f"Host {ip} is {status}" + Style.RESET_ALL)
            file.write(f"Host {ip} is {status}\n")
            if status == "up" and open_ports:
                for port, name in open_ports:
                    print(Fore.YELLOW + f"Open port: {port} ({name})" + Style.RESET_ALL)
                    file.write(f"Open port: {port} ({name})\n")

    up_hosts = [result for result in results if result[1] == "up"]
    down_hosts = [result for result in results if result[1] == "down"]

    print("\nSummary Report:")
    print(Fore.GREEN + f"Total hosts scanned: {len(results)}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Hosts up: {len(up_hosts)}" + Style.RESET_ALL)
    print(Fore.RED + f"Hosts down: {len(down_hosts)}" + Style.RESET_ALL)

    print(Fore.CYAN + f"Time taken for scan: {end_time - start_time:.2f} seconds" + Style.RESET_ALL)
    print(Fore.GREEN + "Completed. Detailed results saved to scan_results.txt" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
