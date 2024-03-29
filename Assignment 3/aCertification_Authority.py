import socket
import threading
import json
from RSA import RSA
import json
from datetime import datetime

HOST = "127.0.0.1"
PORT = 4000

class Certificate ():
    def __init__(self) -> None:
        self.id_a = None
        self.pub_a = None
        self.time = None
        self.duration = None
        self.id_ca = None
        self.cert = None

    def generate_new_certificate (self, id_a, pub_a, duration, id_ca):
        cert = {
            "id":id_a,
            "pub_a":pub_a,
            "time":datetime.now ().timestamp (),
            "duration":duration,
            "id_ca":id_ca
        }
        self.cert = json.dumps (cert)


class CA ():
    def __init__ (self) -> None:
        self.keys = RSA ()
        self.id = "CA"
        self.certs = dict ()

        self.keys.generate_keys ()
        self.keys.save_public_key ("ca.json")
        self.start_server ()
        print('Closing Certificate Authority')


    def start_server (self):
        self.server_threads = []
        try:
            with socket.socket (socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen()
                s.settimeout(10)
                while True:
                    try:
                        conn, addr = s.accept()
                        print(f"Connected by {addr}")
                        th = threading.Thread (target=self.handle_connection, args=(conn,))
                        self.server_threads.append (th)
                        th.start ()

                    except socket.timeout:
                        for th in self.server_threads:
                            th.join ()  
                        print("Timeout!!.. Exiting CA")
                        return
        except KeyboardInterrupt:
            print("Exiting CA")

    def handle_connection (self, connection):
        with connection:
            while True:
                data = connection.recv(1024)
                if not data:
                    break
                self.handle_request (str (data).lstrip ("b'").rstrip ("'"), connection)


    def handle_request (self, request, connection):
        print (request)
        request_type = request.split (";")[0]
        request = request.split (";")[1]
        if (request_type == "csr"):
            print (f"CSR request for {request}")
            cert = self.certificate_signing_request (request)
            connection.sendall (bytes (cert, "UTF-8"))
        else:
            print (f"Certificate request for {request}")
            if (self.certs.get (request) is not None):
                print (f"Certificate request for {request}")
                connection.sendall (bytes (self.certs.get (request), "UTF-8"))


    def certificate_signing_request (self, request):
        request = json.loads (request)
        if (request.get ("id") is None) or (request.get ("public_key") is None):
            return "FAILED"

        cert = Certificate ()
        cert.generate_new_certificate (request.get ("id"),
                                       request.get ("public_key"),
                                       30,
                                       self.id)
        enc = self.keys.encrypt (cert.cert)
        dec = self.keys.decrypt (enc)
        print (dec)
        self.certs[request.get ("id")] = enc
        return enc


if __name__=="__main__":
    ca = CA ()