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

1. Generate two random 256-bit salts (`sA`, `sB`).
2. Use the salts to produce two scrypt hashes of the password (`hA`, `hB`).
3. Send the second hash (`hB`) to the KMS for encryption, using the first hash (`hA`) as 
   authenticated data.
4. Encode the resulting ciphertext, both salts, and the scrypt parameters into an authenticator 
   (`a`).

### Verifying A Password

1. Parse the salts (`sA`, `sB`), the ciphertext (`c`), and the scrypt parameters from the 
   authenticator (`a`).
2. Use the salts to produce two scrypt hashes of the candidate password (`hA`, `hB`).
3. Send the ciphertext (`c`) to the KMS for decryption, using the first hash (`hA`) as 
   authenticated data. If the ciphertext cannot be decrypted, the password is invalid.
4. Compare the plaintext to the second hash (`hB`) using a constant-time algorithm. If they match,
   the password is valid.

## Threat Model

### Offline Application Breach

An attacker with only an offline copy of the stored ciphertexts will be unable to decrypt them
without an authenticated KMS context. Depending on the KMS format, they may learn the KMS key ID or
other metadata.
 
### Online Application Breach

An attacker who is able to suborn the application will be able to make requests to the KMS to test
possible passwords. These requests will be visible in the KMS's audit log, and presumably noticeable
via monitoring and/or rate limiting. Even if application operators remain unaware of the incursion,
password attempts remain limited by KMS request latency.

Such an attacker could presumably see user passwords in plaintext as users authenticate with the
application, too.

### Offline KMS Breach

An attacker who is able to exfiltrate the keys managed by the KMS will be able to decrypt any KMS 
ciphertexts, but won't have access to any.

### Online KMS Breach

An attacker who is able to suborn the KMS will be able to mount DoS attacks, decrypt any KMS
ciphertexts in the future, alter the audit logs, and view any plaintexts sent to the KMS for
encryption. The only plaintext values they will see, however, will be scrypt hashes of user
passwords using unknown 256-bit salts.

A compromised KMS service will not allow an attacker to log into arbitrary accounts, since the
attacker would have to forge an scrypt hash w/o knowing the salt.

### Total Pwnage

An attacker who is able to suborn both the application and the KMS will be able to mount dictionary
attacks against the scrypt password hashes. Whatcha gonna do.