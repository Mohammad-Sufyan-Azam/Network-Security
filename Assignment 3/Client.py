import sys, os
import threading
import socket
import json
from RSA import RSA


def get_credentials(name):
    with open (name, "r") as f:
        data = f.read()
        data = data.split("\n")
        # Remove empty lines
        data = [line for line in data if line.strip() != ""]
        data = [line.split() for line in data]
        data_dic = {}
        for i in data:
            data_dic[i[0]] = i[1:]
    
    return data_dic


class Client ():
    def __init__ (self, ID, Client_ID, INITIATOR, messages, acks, server_address, client_address, ca_address) -> None:
        self.certificate = ""
        self.ID = ID
        self.server_threads = []
        self.keys = RSA()
        self.client_keys = RSA()
        self.keys_path = "keys/"
        self.messages = messages
        self.acks = acks

        self.client_ID = Client_ID
        self.server_address = server_address
        self.client_address = client_address
        self.ca_address = ca_address

        self.keys.generate_keys()
        print (f"{self.ID}'s public key: {self.keys.get_public_key()}")

        self.certificate = self.get_certificate()
        print ("Acquired self Certificate")

        if self.ID == INITIATOR:
            thread_2 = threading.Thread(target=self.communicate, args=())
            thread_2.start()
            thread_2.join()
        else:
            try:
                thread_1 = threading.Thread(target=self.start_server, args=())
                thread_1.start()
                thread_1.join()
            
            except Exception as e:
                print(f"Exiting Client.. {e}")
        
        print('Server thread joined')


    def get_certificate(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.connect(self.ca_address)

            dict = {"ID" : self.ID, "PublicKey" : self.keys.get_public_key()}
            message = "Certificate_Signing_Request;" + json.dumps(dict)
            data = bytes(message, "UTF-8")

            server.sendall(data)
            received_bytes = server.recv(1024)

            return received_bytes.decode("UTF-8")


    def handle_connection(self, connection):
        try:
            with connection:
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    data = data.decode("UTF-8")
                    self.handle_request(data, connection)
            print('Connection closed')
            print('-' * 50, '\n')

        except KeyboardInterrupt:
            print("Exiting")


    def start_server(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(self.server_address)
                s.listen()
                s.settimeout(7)
                self.server_threads = []

                while True:
                    try:
                        conn, addr = s.accept()
                        # print(f"Connected by {addr}")
                        t = threading.Thread(target=self.handle_connection, args=(conn, ))
                        self.server_threads.append(t)
                        t.start()
                        # print('Server thread joined')
                    
                    except Exception as e:
                        print(f"Exiting Client.. {e}")
                        for th in self.server_threads:
                            th.join()
                        return

        except KeyboardInterrupt:
            print("Exiting Client")


    def handle_request(self, request, connection):
        if request == "cert":
            data_ = bytes(self.certificate, "UTF-8")
            connection.sendall(data_)
        else:
            self.request_certificate_of_client()
            request = self.keys.decrypt_pvt(request)
            print("Receiving: ", request)

            if request in self.messages:
                ack = self.acks[self.messages.index(request)]
                data = self.client_keys.encrypt_pub(ack)
                print("Sending: ", ack)
            else:
                data = self.client_keys.encrypt_pub("Invalid message")
                print("Sending: Invalid message")
            
            connection.sendall(bytes(data, "UTF-8"))


    def request_certificate_of_client(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.ca_address)
                data = f"cert;{self.client_ID}"
                s.sendall(bytes(data, "UTF-8"))
                cert = s.recv(1024)
                cert = cert.decode("UTF-8")

            keys = RSA()
            keys.load_public_key("CA_Public_Key.json")
            cert = json.loads(keys.decrypt(cert))
            
            if cert.get("Issuer", "") != "CA":
                print("Invalid certificate")
                return
            
            public_key = json.loads(cert).get("PublicKey")
            print("Public Key:", public_key)
            print("-" * 50)

            self.client_keys.n, self.client_keys.d = int(public_key.split(",")[0]), int(public_key.split(",")[1])
        except:
            print("Invalid certificate")


    def communicate(self):
        print("Requesting certificate")
        self.request_certificate_of_client()

        for message in self.messages:
            enc = self.client_keys.encrypt_pub(message)
            print("Sending: ", message)
            # print("Encrypted: ", enc, " Length: ", len(enc))

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.client_address)
                s.sendall(bytes(enc, "UTF-8"))

                ack = s.recv(1024).decode ("UTF-8")
                print(f"Receiving: {self.keys.decrypt_pvt(ack)}")
            
            print('-' * 50)
        print("Communication done!")



def main():
    CA_ID = "CA"
    INITIATOR = "Client_A"
    MESSAGE_LIST = ["Hello1", "Hello2", "Hello3"]
    ACK_LIST = ["Ack1", "Ack2", "Ack3"]

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

    # get the credentials from the config file
    cred = get_credentials("config.conf")
    server_address = cred[SELF_ID][0], int(cred[SELF_ID][1])
    client_address = cred[CLIENT_ID][0], int(cred[CLIENT_ID][1])
    ca_address = cred[CA_ID][0], int(cred[CA_ID][1])

    Client(SELF_ID, CLIENT_ID, INITIATOR, MESSAGE_LIST, ACK_LIST, server_address, client_address, ca_address)


if __name__=="__main__":
    main()
