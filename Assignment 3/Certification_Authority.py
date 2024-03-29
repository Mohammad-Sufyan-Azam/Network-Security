import socket
import threading
import json
from RSA import RSA
import json
from datetime import datetime

HOST = "127.0.0.1"
PORT = 4000


class CA:
    def __init__(self) -> None:
        self.keys = RSA()
        self.id = "CA"
        self.certs = {}

        self.keys.generate_keys()
        self.keys.save_public_key("CA_Public_Key.json")
        self.start_server()
        print('Closing Certificate Authority')
    

    def generate_new_certificate(self, id, pub, duration, id_ca):
        cert = {
            "ID" : id,
            "PublicKey": pub,
            "IssuanceDate" : datetime.now().timestamp(),
            "Duration" : duration,
            "Issuer": id_ca
        }
        self.cert = json.dumps(cert)


    def start_server(self):
        self.server_threads = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen()
                s.settimeout(10)
                while True:
                    try:
                        conn, addr = s.accept()
                        print(f"Connected by {addr}")
                        th = threading.Thread(target=self.handle_connection, args=(conn,))
                        self.server_threads.append(th)
                        th.start()

                    except socket.timeout:
                        for th in self.server_threads:
                            th.join()
                        print("Timeout!!.. Exiting CA")
                        return
        except KeyboardInterrupt:
            print("Exiting CA")


    def handle_connection(self, connection):
        with connection:
            while True:
                data = connection.recv(1024)
                if not data:
                    break
                self.handle_request(str(data).lstrip("b'").rstrip("'"), connection)


    def handle_request(self, request, connection):
        request_type, request = request.split(";")

        if (request_type == "csr"):
            print (f"CSR request for {request}")
            cert = self.certificate_signing_request(request)
            connection.sendall(bytes(cert, "UTF-8"))
        
        else:
            if (self.certs.get(request) is not None):
                print (f"Certificate request for {request}")
                connection.sendall(bytes(self.certs.get(request), "UTF-8"))
        
        print('-' * 50, '\n')


    def certificate_signing_request(self, request):
        request = json.loads(request)
        if (request.get("ID") is None) or (request.get("PublicKey") is None):
            return "FAILED"

        
        self.generate_new_certificate(request.get("ID"),
                                    request.get("PublicKey"),
                                    30,
                                    self.id)
        enc = self.keys.encrypt(self.cert)
        dec = self.keys.decrypt(enc)
        print(dec)
        self.certs[request.get("ID")] = enc
        return enc


if __name__ == "__main__":
    ca = CA ()