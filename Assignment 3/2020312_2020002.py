'''
a)  Build a public-key certification authority (CA), that responds to requests from clients that seek their own RSA-based public-key 
    certificates OR that of other clients
b)  Build 2 clients that: 
        >   send requests to the CA for their own public-key certificates OR that of other clients, and 
        >   exchange messages with each other in a confidential manner, suitably encrypted with public key of 
            receiver, but only after they know the other client's public key in a secure manner.  
'''
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import json


class CertificateAuthority:
    def __init__(self):
        pass

    # Function to generate RSA key pair
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key


    # Function to create a certificate
    def __create_certificate__(self, user_id, user_public_key, issuer_id, private_key_ca):
        certificate = {
            'ID': user_id,
            'PublicKey': user_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            'Issuer': issuer_id,
            'IssuanceDate': datetime.utcnow().isoformat(),
            'Duration': '365 days'  # For simplicity, we're using a fixed duration
        }

        # Serialize and sign the certificate with CA's private key
        cert_bytes = json.dumps(certificate).encode('utf-8')
        
        # Sign the certificate with CA's private key
        signature = private_key_ca.sign(
            cert_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # The certificate with its signature
        certificate['Signature'] = signature.hex()

        # Save the certificate to a file
        json.dump(certificate, open(f'certificates/{user_id}_certificate.json', 'w'), indent=4)

        return certificate
    

    def get_certificate(self, user_id, user_public_key, issuer_id, private_key_ca):
        if os.path.exists(f'certificates/{user_id}_certificate.json'):
            certificate = json.load(open(f'certificates/{user_id}_certificate.json'))
        else:
            certificate = self.create_certificate(user_id, user_public_key, issuer_id, private_key_ca)
        return certificate


    # Function to verify and decode a certificate
    def verify_certificate(self, certificate, public_key_ca):
        signature = bytes.fromhex(certificate['Signature'])
        cert_copy = certificate.copy()

        del cert_copy['Signature']  # Remove the signature for verification

        cert_bytes = json.dumps(cert_copy).encode('utf-8')
        
        # Verify signature with CA's public key
        try:
            public_key_ca.verify(
                signature,
                cert_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False


    # Function to encrypt a message with RSA
    def encrypt_message(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext


    # Function to decrypt a message with RSA
    def decrypt_message(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')


    # Function to store keys in PEM format
    def __store_keys__(self, key, file, private=True):
        with open(file, 'wb') as f:
            if private:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            else:
                f.write(key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))


    # Function to read keys from PEM files
    def __read_keys__(self, file, private=True):
        with open(file, 'rb') as f:
            if private:
                key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            else:
                key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        return key
    

    # Function to get keys from the files or generate new keys
    def get_keys(self, userID, path='keys/'):
        userID = userID.lower()
        if os.path.exists(f'{path}{userID}_private_key.pem') and os.path.exists(f'{path}{userID}_public_key.pem'):
            private_key = self.__read_keys__(f'{path}{userID}_private_key.pem')
            public_key = self.__read_keys__(f'{path}{userID}_public_key.pem', private=False)
        else:
            private_key, public_key = self.generate_keys()
            self.__store_keys__(private_key, f'{path}{userID}_private_key.pem')
            self.__store_keys__(public_key, f'{path}{userID}_public_key.pem', private=False)
        
        return private_key, public_key



def main():
    # Initialize the Certificate Authority
    CA = CertificateAuthority()

    # Main setup for CA and clients    
    ca_private_key, ca_public_key = CA.get_keys('CA')
    client_a_private_key, client_a_public_key = CA.get_keys('Client_A')
    client_b_private_key, client_b_public_key = CA.get_keys('Client_B')


    # CA issues certificates for client A and B
    cert_a = CA.get_certificate('Client_A', client_b_public_key, 'CA', ca_private_key)
    cert_b = CA.get_certificate('Client_B', client_a_public_key, 'CA', ca_private_key)


    # Clients verify each other's certificate
    if CA.verify_certificate(cert_a, ca_public_key) and CA.verify_certificate(cert_b, ca_public_key):
        # Simulate a series of messages from A to B and responses back from B to A.
        messages_for_b = ['Hello1', 'Hello2', 'Hello3']
        acks_for_a = ['ACK1', 'ACK2', 'ACK3']

        for msg, ack in zip(messages_for_b, acks_for_a):
            # Client A encrypts a message for Client B
            encrypted_message = CA.encrypt_message(msg, client_b_public_key)
            
            # Client B decrypts the message
            decrypted_message = CA.decrypt_message(encrypted_message, client_b_private_key)
            print(f'Client B received: {decrypted_message}')
            
            # Client B sends an acknowledgement to A
            encrypted_ack = CA.encrypt_message(ack, client_a_public_key)
            
            # Client A decrypts the ack
            decrypted_ack = CA.decrypt_message(encrypted_ack, client_a_private_key)
            print(f'Client A received: {decrypted_ack}')
    else:
        print("Certificate verification failed.")


if __name__ == "__main__":
    main()