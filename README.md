# CSE467-assignment-1
CSE467: Computer Security | Spring 2026 | Cryptography Attacks and Vulnerability Analysis

This project explores several classical and modern cryptographic vulnerabilities through practical attacks and implementations. The assignment covers stream cipher key reuse, hash length extension attacks, and RSA signature forgery.

The implementations demonstrate how incorrect use of cryptographic primitives can lead to serious security weaknesses.

## Features

* Many-time pad cryptanalysis
* MD5 length extension attack
* RSA signature forgery using Bleichenbacher's attack
* Practical attack implementations in Python
* Analysis of real-world cryptographic vulnerabilities

## Repository Structure

```text
.
├── CSE467_assignment_1.pdf   # Assignment specification
├── README.md                 # Repository documentation
├── many_time_pad.py          # Many-time pad attack
├── len_ext_attack.py         # MD5 length extension attack
├── bleichenbacher.py         # RSA signature forgery attack
├── pymd5.py                  # MD5 implementation used for length extension
├── roots.py                  # Integer root utilities
└── ctxt.txt                  # Ciphertexts for the many-time pad attack
```

## Implemented Attacks

### Many-Time Pad Attack

Demonstrates the weakness of reusing a one-time pad key across multiple messages.

Features:

* Ciphertext XOR analysis
* Key byte recovery
* Plaintext reconstruction
* Exploitation of English language patterns

### MD5 Length Extension Attack

Demonstrates a vulnerability of Merkle-Damgård hash constructions.

Features:

* Extension of authenticated messages without knowing the secret
* Manipulation of hash-based authentication tokens
* Construction of valid forged requests

### Bleichenbacher RSA Signature Forgery

Demonstrates a signature forgery attack against vulnerable implementations of PKCS #1 v1.5 signature verification.

Features:

* Forged RSA signatures without the private key
* Exploitation of incomplete padding validation
* Integer cube-root based signature construction

## Cryptographic Concepts

The project covers:

* One-time pads
* Stream cipher key reuse
* XOR cryptanalysis
* Message authentication
* Merkle-Damgård hash construction
* MD5 internals
* Length extension vulnerabilities
* RSA digital signatures
* PKCS #1 v1.5 padding
* Signature forgery attacks

## Running

### Many-Time Pad Attack

```bash
python3 many_time_pad.py
```

### Length Extension Attack

```bash
python3 len_ext_attack.py "<url>"
```

### RSA Signature Forgery

```bash
python3 bleichenbacher.py "<message>"
```

## Main Files

### many_time_pad.py

Performs ciphertext analysis and plaintext recovery for messages encrypted using a reused one-time pad.

### len_ext_attack.py

Generates forged URLs using the MD5 length extension vulnerability.

### bleichenbacher.py

Constructs forged RSA signatures that exploit vulnerable PKCS #1 v1.5 verification.

### pymd5.py

Provides MD5 functionality required for the length extension attack.

### roots.py

Provides integer root operations used during RSA signature forgery.

## Technologies

* Python 3
* MD5
* RSA
* PKCS #1 v1.5
* SHA-1

## Course Information

**Course:** CSE467 Computer Security
**Semester:** Spring 2026
