import sys
import threading
import socket
import json
from RSA import RSA


def get_credentials(name):
    with open (name, "r") as f:
        data = f.read ()
        data = data.split ("\n")
        # Remove empty lines
        data = [line for line in data if line.strip () != ""]
        data = [line.split () for line in data]
        data_dic = {}
        for i in data:
            data_dic[i[0]] = i[1:]
    
    return data_dic


class Client ():
    def __init__ (self, ID) -> None:
        self.certificate = ""
        self.ID = ID
        self.keys = RSA ()
        self.client_keys = RSA ()

        self.keys.generate_keys ()
        print (f"Self public key: {self.keys.get_public_key ()}")

        self.certificate = self.get_certificate ()
        print ("Acquired self Certificate")
        th1 = threading.Thread 
        # th1.start ()
        self.server_threads = []

        if self.ID == RESPONDER:
            th2 = threading.Thread (target=self.communicate, args=())
            th2.start ()
            th2.join ()
        else:
            try:
                th1 = threading.Thread (target=self.start_server, args=())
                th1.start ()
                # self.start_server ()
                # for th1_ in self.server_threads:
                #     th1_.join ()
                th1.join()
            except KeyboardInterrupt as e:
                print(f"Exiting Client.. Keyboard Interrupt {e}")
            except Exception as e:
                print(f"Exiting Client.. Keyboard Interrupt {e}")
        
        # th1.join ()
        print('Server thread joined')


    def get_certificate (self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, CA_PORT))
            dict = {
                "id":self.ID,
                "public_key":self.keys.get_public_key (),
            }
            data = bytes (f"csr;{json.dumps (dict)}", "UTF-8")
            s.sendall(data)
            return s.recv(1024).decode ("UTF-8")


    def start_server (self):
        try:
            with socket.socket (socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, SERVER_PORT))
                s.listen()
                s.settimeout(7)
                self.server_threads = []
                while True:
                    try:
                        conn, addr = s.accept()
                        print(f"Connected by {addr}")
                        t = threading.Thread (target=self.handle_connection, args=(conn, ))
                        self.server_threads.append(t)
                        t.start ()
                        # t.join()
                        print('Server thread joined')
                    # except socket.timeout:
                    #     pass
                    except Exception as e:
                        print(f"Exiting Client.. Keyboard Interrupt {e}")
                        # Join all threads and return
                        for th in self.server_threads:
                            th.join()
                        return

        except KeyboardInterrupt:
            print("Exiting Client")


    def handle_connection (self, connection):
        try:
            with connection:
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    print('Received')
                    self.handle_request (data.decode ("UTF-8"), connection)
                    print('Handled')
            print('Connection closed')

        except KeyboardInterrupt:
            print ("Exiting")



    def handle_request (self, request, connection):
        if (request == "cert"):
            connection.sendall (bytes (self.certificate, "UTF-8"))
        else:
            self.request_certificate_of_client ()
            request = self.keys.decrypt_pvt (request)
            print (f"Client: {request}")
            request = request.replace ("Hello", "Ack")
            print (f"Self: {request}")
            data = self.client_keys.encrypt_pub (request)
            connection.sendall (bytes (data, "UTF-8"))


    def request_certificate_of_client (self):
        if CA_MODE:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, CA_PORT))
                data = f"cert;{CLIENT_ID}"
                s.sendall(bytes (data, "UTF-8"))
                cert = s.recv(1024).decode ("UTF-8")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, CLIENT_PORT))
                data = b"cert"
                s.sendall(data)
                cert = s.recv(1024).decode ("UTF-8")

        keys = RSA ()
        keys.load_public_key ("ca.json")
        cert = keys.decrypt (cert)
        try:
            if (json.loads (cert).get ("id_ca", "") != "CA"):
                print ("Invalid certificate")
                return
        except:
            print ("Invalid certificate")
            return
        public_key = json.loads (cert).get ("pub_a")
        print (public_key)
        self.client_keys.n = int (public_key.split (",")[0])
        self.client_keys.d = int (public_key.split (",")[1])


    def communicate (self):
        print ("Requesting certificate")
        self.request_certificate_of_client ()
        for i in range (3):
            print (f"Self: Hello{i}")
            enc = self.client_keys.encrypt_pub (f"Hello{i}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, CLIENT_PORT))
                s.sendall(bytes (enc, "UTF-8"))
                ack = s.recv(1024).decode ("UTF-8")
                print (f"Client: {self.keys.decrypt_pvt (ack)}")
        print ("Communication done")



CA_MODE = 1
CA_ID = "CA"
RESPONDER = "Client_A"

# get the arguement from terminal
arg = sys.argv[1]
if arg == "A":
    SELF_ID = "Client_A"
    CLIENT_ID = "Client_B"
elif arg == "B":
    SELF_ID = "Client_B"
    CLIENT_ID = "Client_A"
else:
    print("Invalid arguement")

a = get_credentials("config.conf")
HOST, SERVER_PORT = a[SELF_ID][0], int(a[SELF_ID][1])
_, CLIENT_PORT = a[CLIENT_ID][0], int(a[CLIENT_ID][1])
_, CA_PORT = a[CA_ID][0], int(a[CA_ID][1])

cl = Client(SELF_ID)

# if SELF_ID == RESPONDER:
#     cl.communicate()

# cl.start_server()

