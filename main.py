#!/usr/bin/python3
import argparse
import nmap
import socket
import requests
import vulners
import signal
from colorama import init,Fore,Back,Style
import warnings

init()
warnings.filterwarnings("ignore", category=DeprecationWarning, module='vulners.*')
vulners_api = vulners.Vulners(api_key="1HM7EKB52GDE1SV8MSN7FGBE24FKYRXELH8M9HO18WGQ3T0IS2AO1J8THSWN8IDY")

def timeout_handler(signum, frame):
    raise TimeoutError("Timeout expired. The operation took too long.")

signal.signal(signal.SIGALRM, timeout_handler)
timeout_duration=20
def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sSV')
    return nm

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"[+] Error: {e}")
        return None

def print_scan_results(nm_scan):
    scan_result={}
    for host in nm_scan.all_hosts():
        print(f"{Fore.GREEN}[+] Host: {Style.RESET_ALL}{host}")
        print("[+] State:", nm_scan[host].state())
        for proto in nm_scan[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm_scan[host][proto].keys()
            for port in ports:
                port_info = nm_scan[host][proto][port]
                print(f"[+] Port: {port}\tState: {port_info['state']}")
                # print(f"\tService_Type: {port_info['name']}",end=" ")
                scan_result[port]=port_info['cpe']
                if 'product' in port_info:
                    print(f"{Fore.GREEN}[+] Service_Name:{Style.RESET_ALL} {port_info['product']}",end=" ")
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

        i=0
        while True:
            try:
                print(f"{Fore.RED} [+] VULNERABILITY FOUND!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] {Fore.RED}ID -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['id']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}CVE-ID -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['cvelist']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}TYPE -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['bulletinFamily']}")
                print(f"{Fore.GREEN}[+] {Fore.RED}TITLE -> {Style.RESET_ALL}{cpe_vulnerabilities_list[i][0]['title']}")
                print()
                i+=1
            except:
                break
        signal.alarm(0)
    except TimeoutError as e:
        print(str(e))
    except Exception as e:
        print(e)
        print(f"{Fore.GREEN}[+] No Vulnerability Found")
        print(f"[+] You  can check the CPE online -> {Style.RESET_ALL}{cpe_name}")

def main():
    banner_D = f"""{Fore.RED}

        DDDD     RRRRR    OOO      PPPP    SSSS    CCCC     AAA     NN   N
        D   D    R   R   O   O     P   P   S      C        A   A    N N  N
        D   D    RRRR    O     O   PPPP    SSS    C        AAAAA    N  N N
        D   D    R R     O   O     P          S   C        A   A    N   NN
        DDDD     R  R     OOO      P       SSSS    CCCC    A   A    N    N
        {Style.RESET_ALL}

    """
    print(banner_D)
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('target', help='Target IP address or domain name')
    args = parser.parse_args()

    target = args.target
    ip = resolve_domain_to_ip(target)
    if ip:
        print(f"Resolved IP Address: {ip}")
        nm_scan = run_nmap_scan(ip)
        scan_result= print_scan_results(nm_scan)
        print(scan_result)
        print("Scanning Open Ports for Vulnerablities")

        for x in scan_result.keys():
            print(f"{Fore.YELLOW}Scanning Port:{x}{Style.RESET_ALL}")
            if  scan_result[x]=='':
                print(f"{Fore.GREEN}NO CPE FOUND!{Style.RESET_ALL}")
            else:
                    search_cve_by_cpe(scan_result[x])

    else:
        print("Failed to resolve domain to IP address.")

if __name__ == '__main__':
    main()
