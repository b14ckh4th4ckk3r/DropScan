# modules/xss.py

from modules.web import *

def scan_xss(url):
    forms = get_all_forms(url)
    
    time.sleep(3)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('hi')</script>"
    
    is_vulnerable = False
    
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"{Fore.RED}[!] XSS Detected on {Style.RESET_ALL}{url}")
            print(f"{Fore.RED}[!] Form details:{Style.RESET_ALL}")
            print(form_details)
            is_vulnerable = True
            print(f"{Fore.GREEN}[+] Remediation: Use sanitization libraries and input validation techniques.{Style.RESET_ALL}")
            print()
        else:
            print(f"{Fore.GREEN}[!] No XSS Vulnerability Detected.{Style.RESET_ALL}")
            print()
        
    return is_vulnerable
