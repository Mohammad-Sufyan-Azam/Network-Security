import datetime
from random import randint
from math import gcd

class RSA:

    def __create_e_and_d__(phi_n):
        try:
            e = randint(phi_n/2, phi_n)
            while (gcd(e, phi_n) != 1):
                e = randint(phi_n/2, phi_n)
            
            d = pow(e, -1, phi_n)
            return e, d
        except:
            print("Error generating e and d key.")


    def generate_keys(p, q):
        try:
            n = p * q
            phi_n = (p-1) * (q-1)
            e, d = RSA.__create_e_and_d__(phi_n)
            return (e, n), (d, n)
        except:
            print("Error generating keys.")
    

    
    
    def get_m_x(m, x, n):
        if x == 1:
            return m % n

        new_m = RSA.get_m_x(m, x//2, n) % n
        new_m = new_m*new_m % n

        if x % 2 == 0:
            return new_m
        else:
            return (new_m*m) % n
        
    def encode_license(license):
        license = license.lower()
        encoded_license = []
        for m in license:
            if m.isalpha():
                encoded_license.append(ord(m) - ord("a"))
            elif m.isdigit():
                encoded_license.append(26 + ord(m) - ord("0"))
        return tuple(encoded_license)
    
    def decode_license(encoded_license):
        license = ""
        for t in encoded_license:
            if t < 26:
                license += chr(t + ord("a"))
            else:
                license += str(t - 26)
        return license
    
    def get_timestamp():
        # Encode the current time in dd-mm-yyyy hh:mm:ss format
        return RSA.encode_license(str(datetime.datetime.now()))
    
    def attackHappened(timestamp, limit):
        # Check if the timestamp is within the limit
        current_time = datetime.datetime.now()
        decoded_time = RSA.decode_license(timestamp)

        msg_time = datetime.datetime.strptime(decoded_time, '%Y%m%d%H%M%S%f')
        if (current_time - msg_time).seconds < limit:
            return False
        return True