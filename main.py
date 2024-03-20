import argparse
import nmap
import socket
import requests
import vulners


vulners_api = vulners.Vulners(api_key="AUYM46WBOGM9GUIOFC0UXS77NABKPJ7O7PRJD5C40A7J5J8MG0P2J8L3LF09WTAL")


def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sSV')
    return nm

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"Error: {e}")
        return None

def print_scan_results(nm_scan):
    scan_result={}
    for host in nm_scan.all_hosts():
        print(f"Host: {host}")
        print("State:", nm_scan[host].state())
        for proto in nm_scan[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm_scan[host][proto].keys()
            for port in ports:
                port_info = nm_scan[host][proto][port]
                print(f"Port: {port}\tState: {port_info['state']}",end=" ")
                print(f"\tService_Type: {port_info['name']}",end=" ")
                scan_result[port]=port_info['cpe']
                if 'product' in port_info:
                    print(f"\tService_Name: {port_info['product']}",end=" ")
                    print(f"\tVersion: {port_info['version']}")
                else:
                    print("\tService information not available")
                
    # print(nm_scan.csv())
    # print(vars(nm_scan))
    # print(scan_result)
    return scan_result

def search_cve_by_cpe(cpe_name):
    cpe_results = vulners_api.get_cpe_vulnerabilities(cpe_name)
    cpe_exploit_list = cpe_results.get('exploit')
    cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
    i=0
    while i<5:
        try:
            print(cpe_vulnerabilities_list[0][i]['id'])
            i+=1
        except:
            break

def main():
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('target', help='Target IP address or domain name')
    args = parser.parse_args()

    target = args.target
    ip = resolve_domain_to_ip(target)
    if ip:
        print(f"Resolved IP Address: {ip}")
        nm_scan = run_nmap_scan(ip)
        scan_result= print_scan_results(nm_scan)
        for x in scan_result.values():
            print("Scanning Open Ports for Vulnerablities")
            print("Scanning Port: "+x)
        #     if  x!='':
        #         search_cve_by_cpe(x)
        #     else:
        #         pass
        search_cve_by_cpe('cpe:/o:linux:linux_kernel')
    else:
        print("Failed to resolve domain to IP address.")

if __name__ == '__main__':
    main()
