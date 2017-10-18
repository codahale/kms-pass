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

1. Generate a random salt (`s`).
2. Use scrypt and the salt (`s`) to produce a hash (`h`) of the password.
3. Generate a random verifier (`v`).
4. Send the verifier (`v`) to the KMS for encryption, using the hash (`h`) as authenticated data.
5. Encode the resulting ciphertext (`c`), the salt (`s`), and the scrypt parameters into an 
   authenticator (`a`).

### Verifying A Password

1. Parse the salt (`s`), the ciphertext (`c`), and the scrypt parameters from the authenticator 
   (`a`).
2. Use scrypt and the salt (`s`) to produce a hash (`h`) of the candidate password.
3. Send the ciphertext (`c`) to the KMS for decryption, using the hash (`h`) as authenticated data.
4. If the ciphertext was decrypted, the password is valid.

## Threat Model

### Local Breach

An attacker with only an offline copy of the stored ciphertexts will be unable to decrypt them
without an authenticated KMS context. Depending on the KMS format, they may learn the KMS key ID or
other metadata.
 
### Persistent Local Incursion

An attacker which establishes a persistent presence inside the application context will be able to
make requests to the KMS to test possible passwords. These requests will be visible in the KMS's
audit log, and presumably noticeable via monitoring.

Also, such an attacker could presumably see user passwords in plaintext as users authenticate with
the application.

### Remote Breach

An attacker who is able to exfiltrate the keys managed by the KMS will be able to decrypt any KMS 
ciphertexts, but won't have access to any.

### Persistent Remote Incursion

An attacker who is able to suborn the KMS will be able to mount DoS attacks, decrypt any KMS
ciphertexts in the future, alter the audit logs, and view any plaintexts sent to the KMS for
encryption. The only plaintext values they will see, however, will be random verifiers and scrypt
hashes of user passwords using unknown 256-bit salts.

### Total Pwnage

An attacker who is able to suborn both the application context and the KMS context will be able to
mount dictionary attacks against the scrypt password hashes. Whatcha gonna do.