#!/usr/bin/env python

import hashlib
import timeit

def compute_hash_with_salt(password, salt):
    salted_password = password + salt
    return hashlib.sha256(salted_password.encode()).hexdigest()

### ---- main ---- ###
def main():
    src_file = "hw3_ex2.txt"
    dictionary_file = "rockyou.txt"

    results = []

    # Read the source file
    with open(src_file) as f:
        passwords_hash = f.readlines()
    passwords_hash = [x.strip() for x in passwords_hash]

    # Extract salts and hashes for ex2c
    passwords_hash_c = passwords_hash[23:33]

    # Separate salts and hashes
    salt_list = []
    hash_list = []
    for item in passwords_hash_c:
        split_item = [x.strip() for x in item.split(',')]
        salt_list.append(split_item[0])
        hash_list.append(split_item[1])

    # Read the dictionary
    with open(dictionary_file, 'r', encoding='latin-1') as f:
        password_dictionary = f.readlines()
    password_dictionary = [x.strip() for x in password_dictionary]

    # Main loop
    start_time = timeit.default_timer()
    for i in range(0, len(salt_list)):
        salt = salt_list[i]
        for password in password_dictionary:
            if compute_hash_with_salt(password, salt) == hash_list[i]:
                print("> {}: {} Found: {}".format(i+1, salt, password))
                results.append(password)
                break

    elapsed = timeit.default_timer() - start_time
    print("> Done")
    print("> Elapsed time: {} seconds".format(elapsed))
    # Copy the results to a file
    output = open("output.txt", "w")
    output_text = ",".join(results)
    print("{}".format(output_text), file=output)
    output.close()

if __name__ == "__main__":
    main()
