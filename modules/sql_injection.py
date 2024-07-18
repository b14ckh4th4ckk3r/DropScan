# modules/sql_injection.py

from modules.web import *

def scan_sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        res = session.get(new_url)
        
        if is_vulnerable(res):
            print(f"{Fore.RED}[!] SQL Injection vulnerability detected, link:{Style.RESET_ALL}{new_url}")
            time.sleep(3)
            print(f"{Fore.GREEN}[+] Remediation: Update your system regularly.{Style.RESET_ALL}")
            return
    
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            
            url = urljoin(url, form_details["action"])
            
            if form_details["method"] == "post":
                res = session.post(url, data=data)
            elif form_details["method"] == "get":
                res = session.get(url, params=data)
            
            if is_vulnerable(res):
                time.sleep(3)
                print(f"{Fore.RED}[+] SQL Injection vulnerability detected, link:{Style.RESET_ALL}{url}")
                print(f"[+] Form:")
                pprint(form_details)
                print()
                break
            else:
                time.sleep(3)
                print(f"{Fore.GREEN}[!] No SQL Vulnerability Detected.{Style.RESET_ALL}")
                print()
