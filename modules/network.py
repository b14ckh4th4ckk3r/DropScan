# modules/network.py

import socket
from colorama import Fore, Style
import signal
from vulners import VulnersApi
import nmap

# Initialize the Vulners API
vulners_api = VulnersApi(api_key="Your_API_KEY")
timeout_duration = 10

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"[+] Error: {e}")
        return None

def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sSV')
    return nm


def print_scan_results(nm_scan):
    scan_result = {}
    for host in nm_scan.all_hosts():
        print(f"{Fore.GREEN}[+] Host: {Style.RESET_ALL}{host}")
        print("[+] State:", nm_scan[host].state())
        for proto in nm_scan[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm_scan[host][proto].keys()
            for port in ports:
                port_info = nm_scan[host][proto][port]
                print(f"[+] Port: {port}\tState: {port_info['state']}")
                print(f"Service_Type: {port_info['name']}", end=" ")
                scan_result[port] = port_info['cpe']
                if 'product' in port_info:
                    print(f"{Fore.GREEN}[+] Service_Name:{Style.RESET_ALL} {port_info['product']}", end=" ")
                    print(f"{Fore.GREEN}\tVersion:{Style.RESET_ALL} {port_info['version']}")
                else:
                    print("\tService information not available")
    return scan_result

def search_cve_by_cpe(cpe_name):
    signal.alarm(timeout_duration)
    try:
        cpe_results = vulners_api.get_cpe_vulnerabilities(cpe_name)
        cpe_exploit_list = cpe_results.get('exploit')
        cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
        print(f"{Fore.RED}[+] VULNERABILITY FOUND!{Style.RESET_ALL}")
        i = 0
        while True:
            try:
                print(f"{Fore.GREEN}[+] {Fore.RED}ID -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['id']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}CVE-ID -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['cvelist']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}TYPE -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['bulletinFamily']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}TITLE -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['title']}")
                print()
                i += 1
            except:
                break
        signal.alarm(0)
    except TimeoutError as e:
        print(str(e))
    except Exception as e:
        print(e)
        print(f"{Fore.GREEN}[+] No Vulnerability Found")
        print(f"[+] You can check the CPE online -> {Style.RESET_ALL}{cpe_name}")
