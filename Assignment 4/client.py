import socket
import json
import sys
import pickle
import time
from RSA import RSA

ip_address_mapping = {1: 4000, 2: 4001, 3: 4002}
rto_ids_name = {1: 'INDIAN RTO', 2: 'DELHI RTO', 3: 'KERALA RTO'}


# Loading ip_address_mapping from json file
# with open('ip_address_mapping.json', 'r') as f:
#     ip_address_mapping = json.load(f)

# rto_ids_name = {}
# with open('rto_ids_name.json', 'r') as f:
#     rto_ids_name = json.load(f)

# if len(sys.argv) < 2:
#     rto_id = 1
# else:
#     rto_id = int(sys.argv[1])

def get_rto_sckt(rto_id):
    # Establishing connection with the central server if no arguments are passed
    rto_port = ip_address_mapping[rto_id]
    rto_sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return rto_sckt, rto_port

def user_menu():
    print("Select the RTO Authority:")
    for rto_id in rto_ids_name:
        print(f"{rto_id}. {rto_ids_name[rto_id]}")
    print("0. Quit")

    rto_id = int(input())
    if rto_id == 0:
        quit()

    print("Enter:")
    print('1. Sign new license')
    print('2. Verify existing license')

    choice = int(input())    
    
    if choice == 1:
        DL_number = input("Enter the Driving License Number: ")
        encoded_doc = RSA.encode_license(rto_ids_name[rto_id]) + RSA.encode_license(DL_number)
        # print(f"Encoded document: {encoded_doc}")
        # Record the timestamp of sending the message to prevent replay attacks
        timestamp = RSA.get_timestamp()
        request_msg = json.dumps({
            'req_type': 3,
            'rto': rto_ids_name[rto_id],
            'doc': encoded_doc,
            'timestamp': timestamp
        })
        # sleep for 6 seconds to check for replay attack
        # time.sleep(6)
        rto_sckt, rto_port = get_rto_sckt(rto_id)
        rto_sckt.connect(('127.0.0.1', rto_port))
        rto_sckt.send(request_msg.encode())
        response = rto_sckt.recv(1024).decode()
        msg_timestamp = json.loads(response)['timestamp']
        if RSA.attackHappened(msg_timestamp, limit=5):
            print("Replay attack detected. Try Again ...")
            return
        doc = json.loads(response)['doc']
        signature = json.loads(response)['signature']
        signingAuthority = json.loads(response)['signingAuthority']
        print(f"Signed document: {doc}\nSignature: {signature}\nSigning Authority: {signingAuthority}")
    
    elif choice == 2:
        # Read the encoded_doc tuple from the user
        encoded_doc = tuple(map(int, input("Enter the encoded document: ").split(', ')))
        signature = int(input("Enter the signature: "))
        signingAuthority_id = int(input("Enter the ID of RTO signing authority from above ids: "))
        timestamp = RSA.get_timestamp()
        request_msg = json.dumps({
            'req_type': 1,
            'rto': rto_ids_name[rto_id],
            'encoded_doc': encoded_doc,
            'signature': signature,
            'signingAuthority': rto_ids_name[signingAuthority_id],
            'timestamp': timestamp
        })
        # time.sleep(6)        
        rto_sckt, rto_port = get_rto_sckt(rto_id)
        rto_sckt.connect(('127.0.0.1', rto_port))
        rto_sckt.send(request_msg.encode())
        response = rto_sckt.recv(1024).decode()
        msg_timestamp = json.loads(response)['timestamp']
        if RSA.attackHappened(msg_timestamp, limit=5):
            print("Replay attack detected. Exiting ...")
            return
        ver_status = json.loads(response)['status']
        print(f"Verification Status: {ver_status}")


while True:
    user_menu()
    print()