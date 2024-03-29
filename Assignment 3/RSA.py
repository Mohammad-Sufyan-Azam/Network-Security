from random import randint
from math import gcd

class RSA ():
    def __init__(self, p=229, q=31) -> None:
        self.n = 0
        self.e = 0
        self.d = 0
        self.p = p
        self.q = q


    def __create_e_and_d__ (self, phi_n):
        try:
            self.e = randint(phi_n/2, phi_n)
            while (gcd(self.e, phi_n) != 1):
                self.e = randint(phi_n/2, phi_n)
            
            self.d = pow (self.e, -1, phi_n)
        except:
            print("Error generating e and d key.")


    def generate_keys (self):
        try:
            self.n = self.p * self.q
            phi_n = (self.p - 1) * (self.q - 1)
            self.__create_e_and_d__ (phi_n)
        except:
            print("Error generating keys.")
    

    def get_public_key (self):
        try:
            public = f"{self.n},{self.d}"
            return (public)
        except:
            print("Error getting public key.")
            return None


    def save_public_key (self, filename):
        try:
            p_key = self.get_public_key()
            if p_key is not None:
                with open (f"{filename}", "w") as f:
                    f.write(p_key)
            else:
                print("Error getting public key to save.")
        except:
            print("Error saving public key.")


    def load_public_key (self, filename):
        try:           
            with open (f"{filename}", "r") as f:
                data = f.read ()
                self.n, self.d = data.split(",")
                self.n, self.d = int(self.n), int(self.d)
        except:
            print("Error loading public key. Try checking file path.")


    def __crypt__(self, data:str, key:int, n:int):
        crypted = ""
        for char in data:
            num = ord (char)
            enc_num = (num ** key) % n
            crypted = crypted + chr (enc_num)
        return crypted


    def encrypt (self, data:str):
        return self.__crypt__ (data, self.e, self.n)

    def decrypt (self, data:str):
        return self.__crypt__ (data, self.d, self.n)

    def encrypt_pub (self, data:str):
        return self.__crypt__ (data, self.d, self.n)

    def decrypt_pvt (self, data:str):
        return self.__crypt__ (data, self.e, self.n)
