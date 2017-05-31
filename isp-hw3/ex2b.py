#!/usr/bin/env python

import itertools
import hashlib
import timeit

def rule1(s):
    return s.title()

def rule2(s):
    return s.replace('e','3')

def rule3(s):
    return s.replace('o','0')

def rule4(s):
    return s.replace('i','1')

def produce_password_variants(password, rules):
    buff = []
    variants = [password]

    rules_index = list(range(0, len(rules)))
    for permutation_length in range(1, len(rules_index)+1):
        for index_combo in itertools.permutations(rules_index, permutation_length):
            variant_builder = password
            for i in index_combo:
                variant_builder = rules[i](variant_builder)
            buff.append(variant_builder)

    # Remove dup
    buff = set(buff)
    # Don't store the original
    for item in buff:
        if item != password:
            variants.append(item)
    return variants

def check_password(password, target_hash_list):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_hash in target_hash_list

### ---- main ---- ###
def main():
    src_file = "hw3_ex2.txt"
    dictionary_file = "rockyou.txt"
    rules = [rule1, rule2, rule3, rule4]

    results = []
    found_count = 0

    # Read the source file
    with open(src_file) as f:
        passwords_hash = f.readlines()
    passwords_hash = [x.strip() for x in passwords_hash]

    # Extract hashes for ex2b
    passwords_hash_b = passwords_hash[12:22]

    # Read the dictionary
    with open(dictionary_file, 'r', encoding='latin-1') as f:
        password_dictionary = f.readlines()
    password_dictionary = [x.strip() for x in password_dictionary]

    # Main loop
    start_time = timeit.default_timer()
    for password in password_dictionary:
        if found_count >= len(passwords_hash_b):
            break
        for password_variant in produce_password_variants(password, rules):
            if check_password(password_variant, passwords_hash_b):
                print("> Found: {}".format(password_variant))
                found_count += 1
                results.append(password_variant)

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
