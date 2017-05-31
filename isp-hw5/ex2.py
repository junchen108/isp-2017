#!/usr/bin/env python

from cothority import Cothority
import binascii
import hashlib
import os

ws_url = 'ws://com402.epfl.ch:7003'
genesis_id_hex = 'a902de6ecd1a61cd8d7a456e18406e559898e530524ed2ba1422077a9d705c21'
mail = 'jun.chen@epfl.ch'

### ---- main ---- ###
def main():
    genesis_id_bin = binascii.unhexlify(genesis_id_hex)

    # Retrieve last_block and last_block_hash
    all_blocks = Cothority.getBlocks(ws_url, genesis_id_bin)
    last_block = all_blocks[-1]
    last_block_hash = last_block.Hash

    # Construct a valid data (a hash that give 0x000000 in the beginning)
    found = False
    valid_data = None
    while not found:
        nonce = os.urandom(32)
        tmp_data = nonce + last_block_hash + mail.encode()
        digest = hashlib.sha256(tmp_data).hexdigest()
        if digest[0:6] == '000000':
            valid_data = tmp_data
            print("> A valid data form has been found. {}".format(digest))
            found = True

    # Add a new block
    new_block = Cothority.createNextBlock(last_block, valid_data)
    output = Cothority.storeBlock(ws_url, new_block)
    print("> Done, check http://com402.epfl.ch/static/conode.html")


if __name__ == "__main__":
    main()
