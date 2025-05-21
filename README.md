Project Title: Applied Cryptography Application

Course Name: CSAC 329 - Applied Cryptography

Date: May 21, 2025


Group Members:

Lily Rose , Julianes

Laurence, Bryan Belen

Laresma, Kathlene 



📌 Introduction

This project shows how cryptography may be used to secure data.  Users can utilize popular cryptographic algorithms to hash, encrypt, and decrypt files and text using an easy-to-use interface.  The software seeks to demonstrate the practical benefits of encryption in safeguarding data integrity and privacy.

🎯 Project Objectives

Put hashing, encryption, and decryption into practice for files and text.  
Support a variety of symmetric and asymmetric cryptography techniques.
Give consumers a straightforward, interactive interface so they can experiment and learn how each algorithm operates.

🧩 Discussions

🏗️ Application Architecture and User Interface

 Streamlit, A browser-based UI framework based on Python, is used to create the application.  It divides features into tabs, such as:  

Encryption and Decryption of Text  
Encrypting and Decrypting files  
File and Text Hashing
Information from Algorithms  
🔒 Cryptographic algorithms were implemented.  

🔐 Symmetric Algorithms  

These both encrypt and decrypt using the same key.  

1.  Advanced Encryption Standard, or AES  

Kind: Symmetric  
Library: The Pycryptodome  
Use: File and text encryption and decryption
Note: Secure and widely used.  Blocks of encryption with a secret key.

2.  Data Encryption Standard, or DES  

Kind: Symmetric  
Library: The Pycryptodome
Use: Encrypting and decrypting text
Note: Older standard, primarily for educational reasons.
🔐 Hashing Features They create fixed-size digests from data that cannot be decrypted.

3. The 256-bit Secure Hash Algorithm, or SHA-256

Library: Hashlib
Use: Text and file hashing•
Note: Frequently found in digital signatures and blockchain.

4. SHA-512

Library: Hashlib •
Use: Text and file hashing•
Note: Greater collision resistance is achieved with a larger digest size.

5. MD5

Library: Hashlib.
Use: Secure but quick hashing
Note: Still helpful for fast file comparison and checksums.

6. BLAKE2b

Library: Hashlib.
Use: Quick and safe hashing
Note: Faster and more secure modern alternative to MD5/SHA.

🖼️ Sample Runs / Output

Symmetric Encryption/Decryption:
Block Cipher (AES):

![1747835681680](https://github.com/user-attachments/assets/4d353fbb-20df-4448-9a8a-da58a218a4ed)
![1747835704307](https://github.com/user-attachments/assets/b7516cc5-11ed-4911-b396-82db52722505)


Stream Ciphere (RC4):

![1747835798954](https://github.com/user-attachments/assets/978120f5-0c54-44d3-860a-9514b977873d)
![1747835803513](https://github.com/user-attachments/assets/e9a26d16-7e9f-4392-b9b6-ef69dd637320)


Vigenère Ciphere:

![1747836191018](https://github.com/user-attachments/assets/ba66d573-c094-4db1-9ca5-e5dfcb2d25b4)
![1747836197763](https://github.com/user-attachments/assets/370fbc33-1507-4c0d-b414-2d8b8aa1b373)


Asymmetric Encryption/Decryption:
RSA:

![1747836635674](https://github.com/user-attachments/assets/bc56192e-b08b-4da1-b2b3-bb710b2a34c2)


Diffie-Hellman:

![1747835975713](https://github.com/user-attachments/assets/bfb7c2ee-4ff2-475c-a711-4a21d11d3afc)


Hashing:
sha256:

![1747836047587](https://github.com/user-attachments/assets/72284552-78de-4ea3-b6a2-a745a23ff06c)


sha512:

![1747836295762](https://github.com/user-attachments/assets/d3ba8768-a52d-4fee-b88b-8d8e31d34387)


md5:

![1747836434618](https://github.com/user-attachments/assets/0cb4a87d-4a27-4455-a6a4-b11a0e46e8bf)


sha1:

![1747836924090](https://github.com/user-attachments/assets/4fa21f57-3378-48c6-82cf-3d3dcf316861)

Algorithm Information:

![1747836132213](https://github.com/user-attachments/assets/b03a87f6-8a9c-4894-9a5b-d509bcf550ca)




 






