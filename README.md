# SecureVault

## Description
Secure Vault is a local password manager aimed at protecting your passwords securely and encrypted without the use of third-party tools.


## Features

- Secure password management with AES-128-CBC encryption and SHA-1 for hash.
- Master password verification through the decryption of a "magic string."
- Import and export of passwords via CSV.
- Random password generation.
- Expiration of password after 90 days (ANSSI Recommandation)


## Prerequisites 

- OpenSSL
- CMake
- C Compiler like GCC

## Installation

1 - Clone the repository

```bash
git clone git@github.com:RemilRLs/SecureVault.git
cd SecureVault
```

2 - Compile the project

```bash
make
```

3 - Ruuuun it :D

```bash
./main
```
