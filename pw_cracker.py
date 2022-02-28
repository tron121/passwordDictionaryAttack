# Author: Ronald
# 
# Passwords are in the format found in /etc/shadow: $[hash_algorithm_id]$[hash_salt]$[hash_data]
#
# This format optionally allows changing the number of rounds each hash function is applied:
# $[hash_algorithm_id]$rounds=[# of rounds]$[hash_salt]$[hash_data]
#
# For this program the salt is prepended to the password and is only applied in the
# first round. The input to the next round of hashing is a hex string of the previous hash digest.
#
# Hash algorithm IDs and default rounds:
# 1 MD5 (1000 rounds)
# 2 Blowfish (64 rounds)
# 5 SHA256 (5000 rounds)
# 6 SHA512 (5000 rounds)
# 

# return list of plaintext passwords in the same order as `passwords_from_file`

import hashlib

from timeit import default_timer as timer

# hashtest is a Hash function with paramaters 'pw' for the plaintext, 'hash_salt' as
# the salt to be used, and 'rounds' as the number of hash rounds.
# Returns 'new_hash', the hash.
def hashtest(pw, hash_salt, rounds):
    for i in range(rounds):
        if i == 0:    
            new_hash = hashlib.sha512( hash_salt + pw)
        else:
            new_hash = hashlib.sha512(new_hash.hexdigest())
    return (new_hash)

# Crack_passwords is a function that retrieves paramaters from formatted hashes in a text file,
# hashes plaintext from a dictionary file with those specifiers, and then prints the plaintexts
# that correspond to the formatted hashes.
def crack_passwords(passwords_from_file):
    with open('dictionary.txt', 'r') as fh:
        wordlist = [line.rstrip('\r\n') for line in fh.readlines()]
        pws = [] # List of plaintexts.
        rectimes = [] # List of recovery times.       
        for h in (passwords_from_file):
            # Start of recovery. 
            start = timer()
            
            # Retrieve hash parameters.           
            if len(h.split('$')) == 5:
                rounds = int(h.split('$')[2].split('=')[1])                             
                hash_salt = h.split('$')[3]            
                hash_data = h.split('$')[4]                                
            else:
                hash_salt = h.split('$')[2]
                hash_data = h.split('$')[3]
                rounds = 5000 # Default rounds for sha512.              

            # simple dictionary attack on hash_data from passwords_from_file
            # with wordlist as a dictionary.
            for pw in (wordlist): 
                if hashtest(pw, hash_salt, rounds).hexdigest() == hash_data:
                    pws.append(pw)
                    end = timer() # End of recovery.
                    rectimes.append(end - start)                      
                    print (pw)
                    break
                else:
                    pass                
      
    return 'plaintexts: ' + str(pws) + '\n' + 'recovery times: ' + str(rectimes)

with open('passwords.txt', 'r') as fh:
    plaintexts = crack_passwords([line.rstrip('\r\n') for line in fh.readlines()])
    print (plaintexts)   
