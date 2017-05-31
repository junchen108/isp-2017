#!/usr/bin/env python

import sys
import requests
import json
import timeit

MAX_TOKEN_LEN = 12
mail = 'jun.chen@epfl.ch'
server_url = 'http://com402.epfl.ch/hw5/ex3'

# My token is '0d7adb49980e'
def sendToken(token):
    start_time = timeit.default_timer()
    r = requests.post(server_url, json = {"email": mail, "token": token})
    elapsed_time = timeit.default_timer() - start_time
    print("> Elapsed time: {} seconds".format(elapsed_time))
    print("> Status code: {}".format(r.status_code))
    print("> Response body: {}".format(r.text))

### ---- main ---- ###
def main():
    if len(sys.argv) == 2:
        token = sys.argv[1]
        sendToken(token)

    if len(sys.argv) == 3:
        if sys.argv[1] == "-test":
            print("Testing mode: a -> a*********** ab -> ab**********")
            testing_part = sys.argv[2]
            remaining_part = ['*']*(MAX_TOKEN_LEN-len(testing_part))
            test_token = testing_part + ''.join(remaining_part)
            print("> Token: {}".format(test_token))
            sendToken(test_token)


if __name__ == "__main__":
    main()
