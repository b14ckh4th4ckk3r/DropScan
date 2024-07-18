#!/usr/bin/python3
import argparse,time, pyfiglet
import nmap
import socket
import requests, platform
import vulners
import signal
from pprint import pprint
from bs4 import BeautifulSoup as bs
from colorama import init,Fore,Back,Style
from urllib.parse import urljoin
import warnings

init()
warnings.filterwarnings("ignore", category=DeprecationWarning, module='vulners.*')
vulners_api = vulners.Vulners(api_key="Your_api-key")

sesson = requests.Session()
sesson.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"


def timeout_handler(signum, frame):
    raise TimeoutError("Timeout expired. The operation took too long.")

signal.signal(signal.SIGALRM, timeout_handler)
timeout_duration=50
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
                print(f"Service_Type: {port_info['name']}",end=" ")
                scan_result[port]=port_info['cpe']
                if 'product' in port_info:
                    print(f"{Fore.GREEN}[+] Service_Name:{Style.RESET_ALL} {port_info['product']}",end=" ")
                    print(f"{Fore.GREEN}\tVersion:{Style.RESET_ALL} {port_info['version']}")
                else:
                    print("\tService information not available")
                
    # print(scan_result)
    return scan_result

def search_cve_by_cpe(cpe_name):
    signal.alarm(timeout_duration)
    try:
        cpe_results = vulners_api.get_cpe_vulnerabilities(cpe_name)
        cpe_exploit_list = cpe_results.get('exploit')
        cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
        print(f"{Fore.RED}[+] VULNERABILITY FOUND!{Style.RESET_ALL}")
        i=0
        while True:
            try:
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


def get_all_forms(url):
    soup = bs(sesson.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    #get form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    
    #get form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    
    #getting input detials such as type and name
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value})
    
    #putting everything to the details dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    #constructing full URL
    target_url = urljoin(url, form_details["action"])
    
    #taking inputs
    inputs = form_details["inputs"]
    data = {}
    
    for input in inputs:
        #replaceing text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        
        input_name = input.get("name")
        input_value = input.get("value")
        
        if input_name and input_value:
            #if input name and value are not None,
            #then add them to the data of form submission
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    
    else:
        # GET request
        return requests.get(target_url, params=data)

def is_vulnerable(response):
    errors = {
        #MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        #SQL Server
        "unclosed quotation mark after the character string",
        #Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        #if any errors found, return True
        if error in response.content.decode().lower():
            return True
    #no error detected
    return False 


def scan_sql_injection(url):
    #testing on URL
    for c in "\"'":
        #add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        #making HTTP request
        res = sesson.get(new_url)
        
        if is_vulnerable(res):
            #SQL Injection detected on the URL itself,
            #no need to preceed for extracting forms and submitting them
            print(f"{Fore.RED}[!] SQL Injection vulnerability detected, link:{Style.RESET_ALL}{new_url}")
            time.sleep(3)
            print(f"{Fore.GREEN}[+] Remedation: Update you system on regular basis.{Style.RESET_ALL}")
            return
    
    #test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            #the data body to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            
            #joining the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            
            if form_details["method"] == "post":
                res = sesson.post(url, data=data)
            
            elif form_details["method"] == "get":
                res = sesson.get(url, params=data)
            
            #testing whether the resulting page is vulnerable
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


def scan_xss(url):
    # geting all the forms from the URL
    forms = get_all_forms(url)
    
    time.sleep(3)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('hi')</script>"
    
    #returning value
    is_vulnerable = False
    
    #iterating over forms
    for form in forms:
        # print(form)
        form_details = get_form_details(form)
        # print(form_details)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"{Fore.RED}[!] XSS Detected on {Style.RESET_ALL}{url}")
            print(f"{Fore.RED}[!] Form details:{Style.RESET_ALL}")
            print(form_details)
            is_vulnerable = True
            print(f"{Fore.GREEN}[+] Remedition: Use sanitization Librairies and User Input Validtion Techinuqes{Style.RESET_ALL}")
            print()
        else:
            print(f"{Fore.GREEN}[!] No XSS Vulnerability Detected.{Style.RESET_ALL}")
            print()
        
    return is_vulnerable


def remote_code_execution(url):
    payload = "system('ls');"
    #sending request to the URL with the payload and retrieve the response
    response = requests.get(url, params={"input": payload})

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "total" in response.text:
        print(f"{Fore.RED}[!] Possible RCE vulnerability detected: command output found in response{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Use Secure Coding Practices.{Style.RESET_ALL}")
        print()
        
    else:
        print(f"{Fore.GREEN}[!] No Remote Code Execution Vulnerability Detected.{Style.RESET_ALL}")
        print()


def security_misconfiguration(url):
    #send a request to the URL and retrieve the response
    response = requests.get(url)

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "Server" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Server Software Version found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Use Latest Security Framework.{Style.RESET_ALL}")
        print()
    
    elif "X-Powered-By" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Server Framework found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Use Latest Security Framework.{Style.RESET_ALL}")
        print()
    
    elif "Set-Cookie" in response.headers:
        print(f"{Fore.RED}[!] Security Misconfiguration: Insecure Cookies found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Use Latest Security Framework.{Style.RESET_ALL}")
        print()
        
    else:
        print(f"{Fore.GREEN}[!] No Security Misconfiguration Vulnerability Detected.{Style.RESET_ALL}")
        print()


def broken_auth(url):
    #set the login credentials
    username = "admin"
    password = "password"

    #send a request to the login page with the credentials and retrieve the response
    response = requests.post(
        url, data={"username": username, "password": password})

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "correct" in response.text:
        print(f"{Fore.RED}[!] Broken Authentication Detected: Incorrect Login Credentials.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Implement Two Factor Authentication.{Style.RESET_ALL}")
        print()
        
    elif "session" in response.cookies:
        print(f"{Fore.RED}[!] Broken Authentication Detected: Session Cookie Found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Implement Two Factor Authentication.{Style.RESET_ALL}")
        print()
    
    else:
        print(f"{Fore.GREEN}[!] No Broken Authenitcation Vulnerability Detected.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Implement Two Factor Authentication.{Style.RESET_ALL}")
        print()


def csrf_scan(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"input": "test"}
    
    #sending a request to the URL and retrieve the response
    response = requests.post(url, headers=headers, data=data)

    #checking the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "error" in response.text:
        print(f"{Fore.RED}[!] CSRF Vulnerability Detected: Error Message found in Response.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Remedation: Use CAPTCHA or Anti-CSRF Token.{Style.RESET_ALL}")
        print()
    
    else:
        print(f"{Fore.GREEN}[!] No CSRF Vulnerability Found.{Style.RESET_ALL}")
        print()

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
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('-c','--choice',choices=['N', 'W'] ,help=' Use -N for network Scan and -W for web scan')
    parser.add_argument('-t','--target', nargs='?', help='Target IP address or domain name')
    parser.add_argument('-u','--url', nargs='?', default=None, help='The URL of the website to scan')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='The timeout for each request (in seconds)')
    parser.add_argument('-o', '--output', type=str, default='report.txt', help='The name of the output file')
    args = parser.parse_args()

    if(args.choice=='N'):
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
    elif(args.choice=='W'):
        print('[*] Target URL:', args.url)
        print('[*] Output file:', args.output)
        
        #peforming vulnerability scans
        time.sleep(args.timeout)
        scan_sql_injection(args.url)
        
        time.sleep(args.timeout)
        scan_xss(args.url)
        
        time.sleep(args.timeout)
        remote_code_execution(args.url)
        
        time.sleep(args.timeout)
        security_misconfiguration(args.url)
        
        time.sleep(args.timeout)
        broken_auth(args.url)
        
        time.sleep(args.timeout)
        csrf_scan(args.url)
    else:
        print("Wrong Arguments")

if __name__ == '__main__':
    main()
