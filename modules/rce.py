# modules/rce.py

from colorama import Fore, Style
from modules.web import *

def remote_code_execution(url):
    payload = "system('ls');"
    response = requests.get(url, params={"input": payload})

    if "total" in response.text:
        print(f"{Fore.RED}[!] Possible RCE vulnerability detected: command output found in response{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Use secure coding practices.{Style.RESET_ALL}")
        print()
    else:
        print(f"{Fore.GREEN}[!] No Remote Code Execution Vulnerability Detected.{Style.RESET_ALL}")
        print()
