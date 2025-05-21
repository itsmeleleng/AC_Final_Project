FP_AC_JULIANES_BELEN_LARESMA_BSCS3A

                 CSAC 329 - Applied Cryptography

                                 Final Project

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

 6. The 256-bit Secure Hash Algorithm, or SHA-256

Hashlib is the library.
Use: Text and file hashing•
Note: Frequently found in digital signatures and blockchain.
7. SHA-512

Hashlib is the library. •
Use: Text and file hashing•
Note: Greater collision resistance is achieved with a larger digest size.
8. MD5

Hashlib is the library.
Use: Secure but quick hashing
Note: Still helpful for fast file comparison and checksums.
9. BLAKE2b

Hashlib is the library.
Use: Quick and safe hashing
Note: Faster and more secure modern alternative to MD5/SHA.
🖼️ Sample Runs / Output

Text Encryption (AES)

 






