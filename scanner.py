# scanner.py

import argparse
import time
from colorama import init, Fore, Style
from modules import *
import warnings


def main():
    banner_D = f"""{Fore.RED}

        DDDD     RRRRR    OOO      PPPP    SSSS    CCCC     AAA     NN   N
        D   D    R   R   O   O     P   P   S      C        A   A    N N  N
        D   D    RRRR    O   O     PPPP    SSS    C        AAAAA    N  N N
        D   D    R R     O   O     P          S   C        A   A    N   NN
        DDDD     R  R     OOO      P       SSSS    CCCC    A   A    N    N
        {Style.RESET_ALL}

    """
    print(banner_D)
    init()
    parser = argparse.ArgumentParser(description="Web and Network Vulnerability Scanner")
    parser.add_argument('-c', '--choice', choices=['N', 'W'], help='Use -N for network scan and -W for web scan')
    parser.add_argument('-t', '--target', nargs='?', help='Target IP address or domain name')
    parser.add_argument('-u', '--url', nargs='?', default=None, help='The URL of the website to scan')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='The timeout for each request (in seconds)')
    parser.add_argument('-o', '--output', type=str, default='report.txt', help='The name of the output file')
    args = parser.parse_args()

    if args.choice == 'N':
        target = args.target
        ip = network.resolve_domain_to_ip(target)
        if ip:
            print(f"Resolved IP Address: {ip}")
            nm_scan = run_nmap_scan(ip)
            scan_result= print_scan_results(nm_scan)
            print("Scanning Open Ports for Vulnerabilities")

            for x in scan_result.keys():
                print(f"{Fore.YELLOW}Scanning Port:{x}{Style.RESET_ALL}")
                if  scan_result[x]=='':
                    print(f"{Fore.GREEN}NO CPE FOUND!{Style.RESET_ALL}")
                else:
                        search_cve_by_cpe(scan_result[x])

        else:
            print("Failed to resolve domain to IP address.")
    elif args.choice == 'W':
        print('[*] Target URL:', args.url)
        print('[*] Output file:', args.output)

        # Performing vulnerability scans
        time.sleep(args.timeout)
        sql_injection.scan_sql_injection(args.url)

        time.sleep(args.timeout)
        xss.scan_xss(args.url)

        time.sleep(args.timeout)
        rce.remote_code_execution(args.url)

        time.sleep(args.timeout)
        security_misconfig.security_misconfiguration(args.url)

        time.sleep(args.timeout)
        broken_authentication.broken_auth(args.url)

        time.sleep(args.timeout)
        csrf.csrf_scan(args.url)
    else:
        print("Wrong Arguments")

if __name__ == '__main__':
    main()
