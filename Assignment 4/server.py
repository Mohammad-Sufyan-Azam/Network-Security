import socket
import sys
from transportAuthority import RTO
import json
from RSA import RSA
import random

if len(sys.argv) < 2:
    quit()
id = int(sys.argv[1])

prime_nos = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


public_keys = {1: (653, 1247), 2: (491, 779), 3: (1309, 1927)}
private_keys = {1: (389, 1247), 2: (371, 779), 3: (149, 1927)}

port_mapping = {1: 4000, 2: 4001, 3: 4002}

rto_id = {1: 'INDIAN RTO',
            2: 'DELHI RTO',
            3: 'KERALA RTO'}

# Load the json files
# with open('public_keys.json', 'r') as f:
#     public_keys = json.load(f)

# with open('private_keys.json', 'r') as f:
#     private_keys = json.load(f)

# with open('rto_ids_name.json', 'r') as f:
#     rto_id = json.load(f)

# with open('ip_address_mapping.json', 'r') as f:
#     port_mapping = json.load(f)

if id not in rto_id.keys():

    print("Invalid ID")
    quit()

def get_rto_obj(id):
    if id == 1:
        rto = RTO(rto_id[id], private_keys[id], public_keys[id], port_mapping[id], hash_method=lambda x: (sum(x) % 27))
        # Adding remaining transport authorities
        for id, name in rto_id.items():
            if id != 1:
                rto.add_rto(name, public_keys[id], f'127.0.0.1:{port_mapping[id]}', central=False)

    else:
        # Generate random no. between 50 and 99
        # hash_val = random.randint(50, 99)
        rto = RTO(rto_id[id], private_keys[id], public_keys[id], port_mapping[id], hash_method=lambda x: (sum(x) % 27))
        # Adding central RTO
        if 1 in rto_id:
            rto.add_rto(rto_id[1], public_keys[1], f'127.0.0.1:{port_mapping[1]}', central=True)
    
    return rto

rto = get_rto_obj(id)

def get_rto_server(rto):
    rto_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rto_server.bind(("", rto.port))
    rto_server.listen(5)
    print(f'{rto.name} is listening on port: {rto.port}')
    return rto_server

def start_rto_server(rto_server):
    while True:
        c, addr = rto_server.accept()
        msg = c.recv(1024).decode()
        msg = json.loads(msg)
        print(f'Received message: {msg} from {addr}')
        msg_rto = msg['rto']
        request_type = msg['req_type']
        msg_timestamp = msg['timestamp']
        if RSA.attackHappened(msg_timestamp, limit=5):
            print("Replay attack detected.")
            continue

        if request_type == 1:
            # Verify the document
            msg_timestamp
            encoded_doc = msg['encoded_doc']
            signature = msg['signature']
            signingAuthority = msg['signingAuthority']
            status = rto.verify(encoded_doc, signature, signingAuthority)
            current_timestamp = RSA.get_timestamp()
            response = json.dumps({
                'status': status,
                'timestamp': current_timestamp
            })
            c.send(response.encode())

        elif request_type == 2:
            info_req_rto = msg['requesting_rto']
            current_timestamp = RSA.get_timestamp()
            response = json.dumps({
                'public_key': rto.get_public_key(info_req_rto),
                'ip_addr': rto.get_ip_address(info_req_rto),
                'timestamp': current_timestamp
            })
            c.send(response.encode())
        elif request_type == 3:
            # Sign the document
            doc = tuple(msg['doc'])
            signature = rto.sign(doc)
            current_timestamp = RSA.get_timestamp()
            response = json.dumps({
                'doc': doc,
                'signature': signature,
                'signingAuthority': rto.name,
                'timestamp': current_timestamp
            })
            c.send(response.encode())
        else:
            print('Invalid request type')
            quit()


rto_server = get_rto_server(rto)

start_rto_server(rto_server)