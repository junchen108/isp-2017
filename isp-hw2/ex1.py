from flask import *
import base64

app = Flask(__name__)

def ascii(a):
    return ord(a[0])

def toChar(i):
    return chr(i)

def compute_xor(amsg, akey):
    result = []
    l = len(amsg)
    for i in range(0, l):
        result.append(amsg[i] ^ akey[i])
    return result

def superencryption(msg, key):
    if len(key) < len(msg):
        diff = len(msg) - len(key)
        key += key[0:diff]

    amsg = list(map(ascii, list(msg)))
    akey = list(map(ascii, list(key[0:len(msg)])))
    res_array = list(map(toChar, compute_xor(amsg, akey)))
    res_str = "".join(res_array)
    res = (base64.b64encode(res_str.encode())).decode()

    return res

@app.route('/hw2/ex1', methods=['POST'])
def check_password():
    if request.method == 'POST':
        data = request.get_json()

        user = data["user"]
        password = data["pass"]
        mySecureOneTimePad = "Never send a human to do a machine's job";

        enc = superencryption(user, mySecureOneTimePad);
        print(enc)
        if (enc != password):
            return "Wrong Password\n", 400
        else:
            return "ok\n", 200
    else:
        return "Not POST\n", 400

if __name__ == "__main__":
    app.run()
