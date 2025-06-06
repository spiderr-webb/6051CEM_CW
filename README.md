# 6051CEM_CW

Solution for coursework of module 6051CEM Practical Cryptography - completed October/November 2023

## What It Does

This program was created to simulate a payment transaction involving three parties - the buyer, the merchant, and the bank - in order to demonstrate the encryption protocol designed as part of this coursework, and to show how it would ensure that the transaction remains secure.

The project directory contains the following files:

`diffie_hellman.py` - Contains functions that can be used by both parties in a communication to carry out a Diffie-Hellman key exchange

`aes.py` - Contains functions to encrypt and decrypt using AES

`tokenisation.py` - Contains a function to calculate the SHA-256 hash of an input

`authenticate.py` - Contains functions to generate and check the validity of digital signatures using RSA

`connection.py` - Shows the flow of information between the three parties involved, including where the above methods would be implemented to ensure security

## How To Use

All files in the directory are required for the program to run. Once these have been downloaded, the program can be run from the CLI by navigating to the project directory and running the command:

`python3 connection.py`

