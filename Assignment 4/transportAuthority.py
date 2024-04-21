import socket
import json
from RSA import RSA

class RTO:
    def __init__(self, name, private_key, public_key, port, hash_method = lambda x: (sum(x) % 83), ip='127.0.0.1'):
        self.name = name
        self.private_key = private_key
        self.public_key = public_key
        self.port = port
        self.central_rto = None
        self.public_keys = {name: public_key}
        self.ip_addresses = {name: f'{ip}:{port}'}
        self.ip = ip
        self.hash_method = hash_method

    def add_rto(self, name, public_key, ip_addr, central=False):
        self.ip_addresses[name] = ip_addr
        self.public_keys[name] = public_key
        if central:
            self.central_rto = name
    
    def get_public_key(self, name):
        if name in self.public_keys:
            return self.public_keys[name]
        public_key, ip_addr = self.request_public_key(name)
        self.add_rto(name, public_key, ip_addr)
        return self.public_keys[name]
    
    def get_ip_address(self, name):
        return self.ip_addresses[name]
    
    def request_public_key(self, name):
        if self.central_rto is None:
            print('No Higher Authority RTO found. Cannot request public key.')
            return None
        central_sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = self.ip_addresses[self.central_rto].split(':')[0]
        port = int(self.ip_addresses[self.central_rto].split(':')[1])
        central_sckt.connect((ip, port))

        current_timestamp = RSA.get_timestamp()
        request = json.dumps({
            'req_type': 2,
            'rto': self.name,
            'requesting_rto': name,
            'timestamp': current_timestamp
        })
        print(f'Requesting public key of {name} from {self.central_rto}')
        print(f'Request: {request} sent to {ip}:{port}')
        central_sckt.send(request.encode())
        response = central_sckt.recv(1024).decode()
        msg_timestamp = json.loads(response)['timestamp']
        if RSA.attackHappened(msg_timestamp, limit=5):
            print("Replay attack detected. Exiting ...")
            return
        rto_public_key = tuple(json.loads(response)['public_key'])
        rto_ip_addr = json.loads(response)['ip_addr']
        return rto_public_key, rto_ip_addr
    
    def sign(self, doc):
        signed_cert = self.hash_method(doc)
        encrypted_sign_cert = RSA.get_m_x(signed_cert, self.private_key[0], self.private_key[1])
        return encrypted_sign_cert
    
    def verify(self, doc, signature, rto):
        doc = tuple(doc)
        signature = signature
        rto_public_key = self.get_public_key(rto)
        if rto_public_key is None:
            print('Cannot verify the document. Public key not found.')
            return False
        decrypted_sign = RSA.get_m_x(signature, rto_public_key[0], rto_public_key[1])
        doc = self.hash_method(doc)
        return decrypted_sign == doc