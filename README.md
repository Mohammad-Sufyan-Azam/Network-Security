# Network Security Projects

## Overview
This repository serves as a hub for various network security projects, beginning with the inaugural mini-project focused on Transposition Matrix Encryption.

### **Mini-Project 1: Transposition Encryption**

**Objective:**
This mini-project demonstrates the implementation of Transposition Matrix Encryption, a cryptographic technique designed to enhance data security during transmission and storage.

**Key Functionalities:**
1. **Encryption:**
   - Utilizes a transposition matrix key to rearrange the order of characters in a message.
   - Implements a modified SHA-256 hash using a character set [a-p] to enhance hashing security.
   - Appends the hash to the data before encryption for added complexity.

2. **Decryption:**
   - Reverses the encryption process, restoring the original data securely.
   - Involves the inverse application of the transposition matrix and modified SHA-256 hash.

3. **Brute Force Attack:**
   - Attempts to decrypt the data without knowing the key by trying all possible permutations of various key lengths.
   - Highlights the resilience of the encryption method against brute force attempts.

**Why Transposition Encryption:**
   - Enhances data confidentiality during transmission and storage.
   - Adds complexity to the encryption process, making it more challenging for adversaries to decipher intercepted messages.
   - Demonstrates an innovative approach to network security in the face of evolving cyber threats.

---
### **Mini-Project 2: DES Algorithm Implementation**

**Objective:**
This mini-project demonstrates the implementation of the Data Encryption Standard (DES) algorithm, a symmetric-key block cipher that provides secure encryption and decryption through multiple rounds of permutation and substitution.

**Key Functionalities:**
1. **Encryption:**
   - Implements the DES algorithm with 16 rounds of key-based transformations.
   - Uses initial and final permutation tables, expansion permutations, and S-boxes for bit-level manipulation.
   - Generates 16 subkeys from the main key using Permutation Choice 1 (PC1) and Permutation Choice 2 (PC2).

2. **Decryption:**
   - Reverses the encryption process to restore the original plaintext.
   - Uses the same DES algorithm but applies the subkeys in reverse order (round 16 to round 1).
   - Verifies the decryption accuracy by comparing with the original plaintext.

3. **Round Verification:**
   - Allows step-by-step verification of intermediate rounds.
   - Stores and returns intermediate results of any specified DES round.
   - Validates encryption and decryption correctness by comparing complementary round pairs (e.g., rounds 1 & 15, 2 & 14).

**Why DES Encryption:**
   - Provides a fundamental understanding of modern cryptographic symmetric encryption algorithms.
   - Showcases the use of permutations, substitutions, and bitwise operations in cryptography.
   - Serves as a foundation for learning more advanced encryption techniques (e.g., AES, 3DES).
   - Demonstrates the importance of key management and round transformations in secure data transmission.

---
### **Mini-Project 3: RSA-Based Public Key Certification Authority**  

**Objective:**  
This mini-project demonstrates the implementation of an **RSA-based Public Key Certification Authority (CA)**, showcasing secure communication through digital certificates, RSA encryption, and client-server interactions.

### **Key Functionalities:**  

1. **Certification Authority (CA):**  
   - **Certificate Generation:** Creates and signs digital certificates for clients.  
   - **Certificate Validation:** Verifies certificate validity, checks expiry, and public key integrity.  
   - **Request Handling:** Listens for and processes client requests (signing/retrieving certificates).  
   - **Timeout Management:** Automatically times out after 10 seconds of inactivity to free system resources.  

2. **Client Operations:**  
   - **Certificate Requests:** Clients can request their own or other clients' certificates from the CA.  
   - **Secure Communication:** Encrypts and decrypts messages using RSA for safe client-to-client communication.  
   - **Connection Management:** Manages connections, sends/receives messages, and handles client-server interactions.  
   - **Timeout Handling:** Clients A and B have built-in timeouts (7 seconds for Client B, immediate for Client A after message exchange).  

3. **RSA Encryption:**  
   - **Key Generation:** Creates public and private key pairs using two prime numbers (`p` and `q`).  
   - **Encryption/Decryption:** Encrypts messages with public keys and decrypts with private keys.  
   - **Key Management:** Saves and loads public keys to/from JSON files for persistence.  

4. **Testing & Verification:**  
   - **Communication Simulation:** Tests message exchange with sample messages ("Hello" and "Ack").  
   - **Certificate Verification:** Ensures encryption, decryption, and certificate validation are functioning correctly.  
   - **Batch File Support:** Includes a `delete.bat` file to clear existing certificates and keys for fresh execution.  


#### **How to Run:**  

1. Start three terminal instances:  
   - Run the Certification Authority:  
     ```bash  
     python Certification_Authority.py  
     ```  

   - Start Client B:  
     ```bash  
     python Client.py B  
     ```  

   - Start Client A:  
     ```bash  
     python Client.py A  
     ```  

2. The clients will exchange test messages, and the CA will issue or verify certificates as needed.  



**Why RSA-Based Certification Authority:**
   - **Strong Security:** RSA encryption resists brute-force attacks due to the difficulty of factoring large prime numbers.  
   - **Digital Identity Management:** Simulates real-world public key infrastructure (PKI) concepts like certificate authorities and digital signatures.  
   - **Hands-On Learning:** Offers a practical understanding of secure message exchange, key management, and socket programming.  

---
### **Mini-Project 4: KAVACH - Unmasking the Road Rash (On-the-Go Driver’s License Verification)**  

**Objective:**  
This project implements a Driver’s License (DL) verification system using RSA encryption, digital signatures, and hash functions to ensure secure, tamper-proof license verification. It includes replay attack prevention and supports decentralized RTO (Regional Transport Office) servers for fault tolerance and scalability.  

**Key Functionalities:**
1. **Digital License Issuance & Signing:**  
   - The RTO server signs new DLs using its private key.  
   - Generates a **hash value** of the DL ID to maintain data integrity.  

2. **License Verification:**  
   - Police officers scan DL codes and send encrypted data to their local RTO server.
   - If the license was issued by the same RTO, verification is done locally.
   - If issued elsewhere, the local RTO contacts the **central RTO** to fetch the public key of the signing authority for verification.

3. **2-Step Verification Process:**  
   - **Hash Verification:** Ensures the data hasn’t been tampered with.
   - **Signature Verification:** Uses the public key of the signing RTO to verify the DL’s authenticity.

4. **Replay Attack Prevention:**
   - Each message includes a **timestamp**.
   - The server checks the timestamp, discards messages with delays beyond a threshold, preventing malicious replays.

#### **How to Run:**  

1. Start the RTO server:  
```bash  
python server.py  
```  

2. Start the client (Police Officer):  
```bash  
python client.py  
```  

3. Simulate DL issuance or verification based on user prompts.  

#### **Why KAVACH for License Verification:**  
   - **Security:** RSA encryption and digital signatures provide authentication, integrity, and non-repudiation.  
   - **Scalability:** The system works with local RTOs, minimizing dependence on a central server unless necessary.  
   - **Attack Mitigation:** Prevents replay attacks using timestamp-based checks.  
   - **Real-World Relevance:** Mimics practical applications like traffic law enforcement, e-governance, and national ID systems.