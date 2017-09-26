# kms-pass

An experiment in secure password storage using a trusted third party.

**NOT A REAL THING, DO NOT USE THIS**

## The Problem

Storing passwords is hard. In the event of a breach, the contents of your database need to be
resistant to brute-force and dictionary attacks. This leads us to memory-hard algorithms like Scrypt
and Argon2, which level the computational playing field by running as slowly on ASICs and GPUs as
they do on general-purpose CPUs.

This is a good solution to reduce the scope of a breach, but does little to protect individual
passwords: limiting an attacker to tens of megahashes/sec still allows for targeted attacks against
low entropy passwords (i.e. 99% of passwords).

The fundamental problem is that an offline attack allows an attacker to bring unlimited
computational resources to bear across unlimited amounts of time and space. Once a breach occurs,
attackers have the rest of their lives to recover the passwords.

How do we fix this? We move the problem to an exclusively online system.

## The Solution

kms-pass implements a proposed solution which uses a managed cryptographic service like Google Cloud
Platform's Key Management Service to isolate a critical piece of information required for verifying
a candidate password.

### Storing A Password

1. Use HMAC-SHA2-256 and the system key (`sk`) to calculate a digest (`d`) of the user's password.
2. Use the Key Management Service to encrypt (`ed`) the digest.
3. Generate a key (`ek`) using scrypt, a random salt (`s`), and the user's password.
4. Encrypt (`eed`) the encrypted digest (`ed`) using AES-CTR and `ek`.
5. Store the salt (`s`), the scrypt params, and the doubly-encrypted digest (`eed`).

### Verifying A Password

1. Generate a key (`ek`) using scrypt, a random salt (`s`), and the user's password.
2. Decrypt the doubly-encrypted digest using `ek`.
3. Use Key Management Service to decrypt the encrypted digest.
4. Use HMAC and the system key to calculate a candidate digest of the user's password.
5. Use a constant-time comparison algorithm to compare the decrypted digest with the candidate.

