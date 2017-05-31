#!/usr/bin/env python3

from flask import *
import base64
import hmac
import os
import hashlib
#import sys

app = Flask(__name__)

key = "JBAYSxFIFgsuAVAHTEYWBQ=="
USER_TYPE = ["administrator", "user"]

def isAdmin(user, password):
    return (user == "administrator") and (password == "42")

def generate_cookie(user, user_type):
    nonce = int.from_bytes(os.urandom(8), 'big')
    info = user + "," + str(nonce) + ",com402,hw2,ex3," + user_type
    #sys.stderr.write("info: " + info + "\n")
    digest = hmac.new(key.encode(), info.encode(), hashlib.sha256).hexdigest()
    cookie = info + "," + digest
    #sys.stderr.write("cookie: " + cookie + "\n")
    cookie_enc = base64.b64encode(cookie.encode()).decode()
    return cookie_enc

def compare_hmac(info, digest_to_compare):
    digest = hmac.new(key.encode(), info.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, digest_to_compare)

@app.route('/ex3/login', methods=['POST'])
def login():
    if request.headers['Content-Type'] != 'application/json':
        abort(400)

    data = request.get_json()

    user = data['user']
    #sys.stderr.write("user: " + user + "\n")
    password = data['pass']
    #sys.stderr.write("password: " + password + "\n")

    cookie_value = ''
    if isAdmin(user, password):
        cookie_value = generate_cookie(user, USER_TYPE[0])
    else:
        cookie_value = generate_cookie(user, USER_TYPE[1])

    #sys.stderr.write("cookie_value: " + cookie_value + "\n")

    response = make_response("hello")
    response.set_cookie('LoginCookie', cookie_value)

    return response

@app.route('/ex3/list', methods=['POST'])
def check_cookie():
    cookie_value = request.cookies.get('LoginCookie')
    #sys.stderr.write("cookie_value: " + cookie_value + "\n")
    cookie_str = base64.b64decode(cookie_value.encode()).decode()
    #sys.stderr.write("cookie_info: " + cookie_str + "\n")
    cookie_str_split = [x.strip() for x in cookie_str.split(',')]

    digest_to_compare = cookie_str_split[-1]
    user_type = cookie_str_split[-2]
    info_reconstruct = ",".join(cookie_str_split[0:len(cookie_str_split)-1])

    if compare_hmac(info_reconstruct, digest_to_compare):
        if user_type == USER_TYPE[0]:
            return "Welcome, admin\n", 200
        elif user_type == USER_TYPE[1]:
            return "Welcome\n", 201
    else:
        return abort(403)

if __name__ == "__main__":
    app.run()
