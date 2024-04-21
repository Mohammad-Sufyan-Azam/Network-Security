from RSA import RSA

import socket
import sys
from transportAuthority import RTO
import json
from RSA import RSA
import random


prime_nos = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


port_mapping = {1: 4000, 2: 4001, 3: 4002}

rto_id = {1: 'INDIAN RTO',
            2: 'DELHI RTO',
            3: 'KERALA RTO'}

public_keys = {}
private_keys = {}

for id in rto_id.keys():
    # Generate random prime numbers
    prime_idx = random.randint(0, len(prime_nos)-1)
    p = prime_nos[prime_idx]
    prime_nos.pop(prime_idx)
    prime_idx = random.randint(0, len(prime_nos)-1)
    q = prime_nos[prime_idx]
    prime_nos.append(p)   
    public_keys[id], private_keys[id] = RSA.generate_keys(p, q)

# Dump the keys
with open('public_keys.json', 'w') as f:
    json.dump(public_keys, f)

with open('private_keys.json', 'w') as f:
    json.dump(private_keys, f)

with open('rto_ids_name.json', 'w') as f:
    json.dump(rto_id, f)

with open('ip_address_mapping.json', 'w') as f:
    json.dump(port_mapping, f)
