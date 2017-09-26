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

1. A random 128-bit salt is created.
2. The salt is prepended to an arbitrary, system-wide secret key.
3. The resulting value is used as the key for an HMAC.
4. The HMAC is used to hash the password.
5. The salt is sent to the Key Management Service to be encrypted with a managed key.
6. The resulting ciphertext is prepended to the HMAC digest and stored.

### Verifying A Password

1. The salt ciphertext is separated from the HMAC digest.
2. The salt ciphertext is sent to the Key Management Service to be decrypted.
3. The resulting plaintext is prepended to the system-wide secret key.
4. The resulting value is used as the key for an HMAC.
5. The HMAC is used to hash the password.
6. The candidate digest is compared to the stored digest using a constant-time algorithm.


