#!/usr/bin/env python

import itertools
import hashlib

def generate_passwords(charset, min_length, max_length):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i)
        for i in range(min_length, max_length + 1)))

def check_password(password, target_hash_list):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_hash in target_hash_list

### ---- main ---- ###
def main():
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
    src_file = "hw3_ex2.txt"

    found_count = 0
    results = []

    # Read the source file
    with open(src_file) as f:
        passwords_hash = f.readlines()
    passwords_hash = [x.strip() for x in passwords_hash]

    # Extract hashes for ex2a
    passwords_hash_a = passwords_hash[1:11]

    # Main loop
    for password in generate_passwords(charset, 4, 6):
        if found_count >= len(passwords_hash_a):
            break
        if check_password(password, passwords_hash_a):
            print("> Found: {}".format(password))
            found_count += 1
            results.append(password)

    print("> Done")

    # Copy the results to a file
    output = open("output.txt", "w")
    output_text = ",".join(results)
    print("{}".format(output_text), file=output)
    output.close()

if __name__ == "__main__":
    main()
