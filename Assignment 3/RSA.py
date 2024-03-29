from random import randint
from math import gcd
import json

class RSA ():
    def __init__(self) -> None:
        self.n = 0
        self.e = 0
        self.d = 0


    def generate_keys (self):
        p = 229
        q = 31
        self.n = p*q
        phi_n = (p-1) * (q-1)
        self.e = randint (phi_n/2, phi_n)
        while (gcd (self.e, phi_n) != 1):
            self.e = randint (phi_n/2, phi_n)
        self.d = pow (self.e, -1, phi_n)


    def get_public_key (self):
        public = f"{self.n},{self.d}"
        return (public)


    def save_public_key (self, filename):
        with open (f"{filename}", "w") as f:
            f.write (self.get_public_key ())

    def load_public_key (self, filename):
        with open (f"{filename}", "r") as f:
            data = f.read ()
            self.n = int (data.split (",")[0])
            self.d = int (data.split (",")[1])

    def encrypt (self, data:str):
        encrypted = ""
        for char in data:
            num = ord (char)
            enc_num = (num ** self.e) % self.n
            encrypted = encrypted + chr (enc_num)
        return encrypted

    def decrypt (self, data:str):
        decrypted = ""
        for char in data:
            num = ord (char)
            dec_num = (num ** self.d) % self.n
            decrypted = decrypted + chr (dec_num)
        return decrypted

    def encrypt_pub (self, data:str):
        encrypted = ""
        for char in data:
            num = ord (char)
            enc_num = (num ** self.d) % self.n
            encrypted = encrypted + chr (enc_num)
        return encrypted

    def decrypt_pvt (self, data:str):
        decrypted = ""
        for char in data:
            num = ord (char)
            dec_num = (num ** self.e) % self.n
            decrypted = decrypted + chr (dec_num)
        return decrypted




# if __name__ == "__main__":
#     rsa = RSA ()
#     rsa.generate_keys ()
#     c = rsa.encrypt_pub ("md5678")
#     print (c)
#     p = rsa.decrypt_pvt (c)
#     print (p)