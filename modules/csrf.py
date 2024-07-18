# modules/csrf.py

from colorama import Fore, Style
from modules.web import *

def csrf_scan(url):
    headers = {"Referer": "https://evil.com"}
    response = requests.get(url, headers=headers)

    if "csrf" in response.text.lower():
        print(f"{Fore.RED}[!] CSRF Detected: Lack of CSRF Protection.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Implement CSRF tokens.{Style.RESET_ALL}")
        print()
    else:
        print(f"{Fore.GREEN}[!] No CSRF Vulnerability Detected.{Style.RESET_ALL}")
        print()
