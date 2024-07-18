# modules/broken_auth.py

from modules.web import *

def broken_auth(url):
    username = "admin"
    password = "password"

    response = requests.post(url, data={"username": username, "password": password})

    if "correct" in response.text:
        print(f"{Fore.RED}[!] Broken Authentication Detected: Incorrect Login Credentials.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Implement two-factor authentication.{Style.RESET_ALL}")
        print()
    elif "session" in response.cookies:
        print(f"{Fore.RED}[!] Broken Authentication Detected: Session Cookie Found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remediation: Implement two-factor authentication.{Style.RESET_ALL}")
        print()
    else:
        print(f"{Fore.GREEN}[!] No Broken Authentication Vulnerability Detected.{Style.RESET_ALL}")
        print()
