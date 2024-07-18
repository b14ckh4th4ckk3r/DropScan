# modules/web.py

import requests
import time
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from colorama import Fore, Style

session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/83.0.4103.106 Safari/537.36"
)

def get_all_forms(url):
    soup = bs(session.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    
    method = form.attrs.get("method", "get").lower()
    
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        
        input_name = input.get("name")
        input_value = input.get("value")
        
        if input_name and input_value:
            data[input_name] = input_value

    print(f"[+] Submitting payload to {target_url}")
    print(f"[+] Data: {data}")
    
    if form_details["method"] == "post":
        return session.post(target_url, data=data)
    else:
        return session.get(target_url, params=data)

def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False
