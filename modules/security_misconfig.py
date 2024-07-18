# modules/security_mis_config.py

from colorama import Fore, Style
from modules.web import *

def security_misconfiguration(url):
    response = requests.get(url)

    if "Server" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Server Software Version found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Use latest security framework.{Style.RESET_ALL}")
        print()
    elif "X-Powered-By" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Server Framework found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Use latest security framework.{Style.RESET_ALL}")
        print()
    elif "Set-Cookie" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Insecure Cookies found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Use latest security framework.{Style.RESET_ALL}")
        print()
    else:
        print(f"{Fore.GREEN}[!] No Security Misconfiguration Vulnerability Detected.{Style.RESET_ALL}")
        print()
