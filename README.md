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

Library: Hashlib
Use: Text and file hashing•
Note: Frequently found in digital signatures and blockchain.

7. SHA-512

Library: Hashlib •
Use: Text and file hashing•
Note: Greater collision resistance is achieved with a larger digest size.

8. MD5

Library: Hashlib.
Use: Secure but quick hashing
Note: Still helpful for fast file comparison and checksums.

9. BLAKE2b

Library: Hashlib.
Use: Quick and safe hashing
Note: Faster and more secure modern alternative to MD5/SHA.

🖼️ Sample Runs / Output
Text Encryption (AES)

 ![1000000458](https://github.com/user-attachments/assets/f33e1878-6316-47a2-8a7a-262c9ef5b269)
![1000000459](https://github.com/user-attachments/assets/9e69931b-47ad-48e8-98c7-ab88daaae8df)
![1000000460](https://github.com/user-attachments/assets/407ff26d-e86e-4db5-98ec-13693487078e)
![1000000461](https://github.com/user-attachments/assets/8efd7b84-bb25-46a2-8157-7adbf6d71175)
![1000000462](https://github.com/user-attachments/assets/10d544d2-d420-40cd-9380-f9ac4806157d)






