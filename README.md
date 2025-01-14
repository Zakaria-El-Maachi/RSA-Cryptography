# RSA Project

## Overview
This project is a comprehensive exploration of the RSA cryptographic algorithm. It includes:
- **Plain RSA implementation**: From generating primes using the Miller-Rabin primality test to encryption and decryption functionalities.
- **RSA Attacks**: Implementation of various attacks on RSA such as small message brute-forcing, message product attacks, and factorization attacks including Pollard's rho and Fermat's method.
- **Secure RSA**: A secure RSA implementation using the SAEP padding scheme for message preprocessing.
- **Secure Messaging App**: A socket-based application that enables secure communication over a local network using the secure RSA implementation.

## Features

### 1. Plain RSA Implementation
- **Prime Generation**: Uses the Miller-Rabin primality test to generate large prime numbers.
- **Key Generation**: Generates public and private keys based on the RSA algorithm.
- **Encryption/Decryption**: Implements the basic RSA encryption and decryption functions.

### 2. RSA Attacks
- **Small Message Brute-forcing**: Attempts to brute-force small messages encrypted with RSA.
- **Message Product Attack**: Exploits the properties of the product of messages.
- **Factorization Attacks**:
  - **Pollard's Rho**: An efficient algorithm for integer factorization.
  - **Fermat's Method**: Another approach to factorization based on representing an odd integer as the difference of two squares.

### 3. Secure RSA Implementation
- **SAEP Padding Scheme**: Preprocesses the message using the SAEP padding scheme for added security.
- **Secure Encryption/Decryption**: Utilizes the plain RSA algorithm on the padded message.

### 4. Secure Messaging App
- **Socket-based Communication**: Allows users on the same local network to securely communicate.
- **Encryption with Secure RSA**: Messages are encrypted using the secure RSA implementation with SAEP padding.
- **User-friendly**: Users only need to enter the correspondent's IP address to start communicating securely.

### Prerequisites
- Python 3.9
