#!/usr/bin/env python3

from flask import *
import bcrypt

app = Flask(__name__)

@app.route('/hw4/ex2', methods=['POST'])
def hashPassword():
    if request.method == 'POST':
        data = request.get_json()

        user = data['user']
        password = data['pass']

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        return hashed_password, 200
    else:
        return "Not POST\n", 400

if __name__ == "__main__":
    app.run()
