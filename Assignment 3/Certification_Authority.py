import os
import socket
import threading
import json
from RSA import RSA
import json
from datetime import datetime, timedelta


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


class CA:
    def __init__(self, host, port) -> None:
        self.id = "CA"
        self.certs = {}
        self.address = (host, port)

        self.keys = RSA()
        # self.keys_path = "keys/"
        self.keys.generate_keys()
        self.keys.save_public_key("CA_Public_Key.json")

        self.server()
        print('Closing Certificate Authority')
    

    def __create_certificate__(self, id, pub, id_ca, duration):
        cert = {
            "ID" : id,
            "PublicKey": pub,
            "IssuanceDate" : datetime.utcnow().isoformat(),
            "Duration" : duration,
            "Issuer": id_ca
        }
        return cert


    def __verify_certificate_validity__(self, certificate):
        '''Checks if the certificate has expired or not'''
        
        duration = certificate['Duration'].lower()
        map_ = {'days': 0, 'seconds': 0, 'microseconds': 0, 'milliseconds': 0, 'minutes': 0, 'hours': 0, 'weeks': 0}
        duration = duration.split(' ')

        for i in range(len(duration)):
            if duration[i] in map_.keys():
                map_[duration[i]] = int(duration[i-1])

        # Creating a timedelta object for the duration
        duration = timedelta(days=map_['days'], seconds=map_['seconds'], microseconds=map_['microseconds'], milliseconds=map_['milliseconds'], minutes=map_['minutes'], hours=map_['hours'], weeks=map_['weeks'])

        # Getting the expiry date of the certificate by adding the duration to the issuance date
        issuance_date = datetime.strptime(certificate['IssuanceDate'], '%Y-%m-%dT%H:%M:%S.%f')
        expiry =  (issuance_date + duration).isoformat()

        # Checking if the certificate has expired
        if (datetime.utcnow()).isoformat() >= expiry:
            return False
        return True


    def get_certificate(self, user_id, user_public_key, issuer_id, duration='365 days', path='certificates/'):
        # Checking if the certificate already exists
        if os.path.exists(f'{path}{user_id}_certificate.json'):
            certificate = json.load(open(f'{path}{user_id}_certificate.json'))

            if certificate.get("PublicKey") != user_public_key:
                print(f"Public key for {user_id} has been changed. Generating a new certificate.")
                certificate = self.__create_certificate__(user_id, user_public_key, issuer_id, duration=duration)
                json.dump(certificate, open(f'certificates/{user_id}_certificate.json', 'w'), indent=4)

            # Checking if the certificate is still valid
            if not self.__verify_certificate_validity__(certificate):
                print(f"The previous certificate for {user_id} has been expired. Generating a new one.")
                certificate = self.__create_certificate__(user_id, user_public_key, issuer_id, duration=duration)
                json.dump(certificate, open(f'certificates/{user_id}_certificate.json', 'w'), indent=4)
        
        else:
            if not os.path.exists(path):
                os.makedirs(path)
            
            # Creating a new certificate
            certificate = self.__create_certificate__(user_id, user_public_key, issuer_id, duration=duration)
            json.dump(certificate, open(f'certificates/{user_id}_certificate.json', 'w'), indent=4)

        certificate = json.dumps(certificate)
        self.cert = certificate
        return certificate


    def server(self):
        self.server_threads = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(self.address)
                s.listen()
                s.settimeout(10)
                while True:
                    try:
                        conn, addr = s.accept()
                        # print(f"Connected by {addr}")
                        th = threading.Thread(target=self.handle_connection_request, args=(conn,))
                        self.server_threads.append(th)
                        th.start()

                    except socket.timeout:
                        for th in self.server_threads:
                            th.join()
                        print("Timeout!!.. Exiting CA")
                        return
        
        except KeyboardInterrupt:
            print("Exiting the Certificate Authority Server...")


    def handle_connection_request(self, connection):
        with connection:
            while True:
                data = connection.recv(1024)
                if not data:
                    break

                request = str(data)
                request = request.lstrip("b'").rstrip("'")

                request_type, request = request.split(";")
                if (request_type == "Certificate_Signing_Request"):
                    print ("Certificate Signing Request For", request)
                    cert = self.sign_certificate_request(request)
                    connection.sendall(bytes(cert, "UTF-8"))
                else:
                    if (self.certs.get(request) is not None):
                        print (f"Certificate request for {request}")
                        connection.sendall(bytes(self.certs.get(request), "UTF-8"))
                print('-' * 50, '\n')


    def sign_certificate_request(self, request):
        request = json.loads(request)

        # Check if ID and PublicKey are present in the request
        if (request.get("ID") is None) or (request.get("PublicKey") is None):
            return "FAILED"
        
        certificate = self.get_certificate(user_id=request.get("ID"), user_public_key=request.get("PublicKey"), issuer_id=self.id, duration='365 days')

        enc = self.keys.encrypt(certificate)
        dec = self.keys.decrypt(enc)

        print("Certificate:\n", dec)
        self.certs[request.get("ID")] = enc
        print("Certificate signed successfully")

        return enc


if __name__ == "__main__":
    cred = get_credentials("config.conf")
    host, port = cred["CA"][0], int(cred["CA"][1])
    ca = CA (host, port)