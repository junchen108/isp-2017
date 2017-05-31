#!/usr/bin/env python

import asyncio
import websockets

import binascii
import os
import hashlib

g = 2
N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
mail = "jun.chen@epfl.ch"
password = "JBAYSxFIFgsuAVAHTEYWBQ=="

def int_to_bin(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

def bin_to_int(b):
    return int.from_bytes(b, 'big')

def hex_to_bin(h):
    return binascii.unhexlify(h)

def int_to_hex(i):
    buff = int_to_bin(i)
    strToSend = binascii.hexlify(buff).decode()
    return strToSend

def hex_to_int(msgReceived):
    buff = hex_to_bin(msgReceived)
    i = bin_to_int(buff)
    return i

def generate_random_int():
    return bin_to_int(os.urandom(16))

def compute_secret(A, B, a, salt, mail, password, N):
    u_hex = hashlib.sha256(int_to_bin(A) + int_to_bin(B)).hexdigest()
    u = hex_to_int(u_hex)
    info = mail + ":" + password
    info_hash = hashlib.sha256(info.encode()).hexdigest()
    x_hex = hashlib.sha256(int_to_bin(salt) + hex_to_bin(info_hash)).hexdigest()
    x = hex_to_int(x_hex)
    secret = pow(B - pow(g, x, N), a + u * x, N)
    return secret

def compute_submission(A, B, S):
    result = hashlib.sha256(int_to_bin(A) + int_to_bin(B) + int_to_bin(S)).hexdigest()
    return result

async def pake():
    async with websockets.connect('ws://com402.epfl.ch/hw2/ws') as websocket:

        N = hex_to_int(N_hex)

        await websocket.send(mail)
        print('> mail = {}'.format(mail))

        salt_hex = await websocket.recv()
        salt = hex_to_int(salt_hex)
        print('< salt = {}'.format(salt))

        a = generate_random_int()
        print('> a = {}'.format(a))
        A = pow(g, a, N)
        A_hex = int_to_hex(A)
        await websocket.send(A_hex)
        print('> A = {}'.format(A))

        B_hex = await websocket.recv()
        B = hex_to_int(B_hex)
        print('< B = {}'.format(B))

        secret = compute_secret(A, B, a, salt, mail, password, N)
        print('> secret = {}'.format(secret))

        # Submission
        result = compute_submission(A, B, secret)
        await websocket.send(result)
        token = await websocket.recv()
        print('< token = {}'.format(token))

asyncio.get_event_loop().run_until_complete(pake())
