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

In short:

``` 
hash = aes(scrypt(systemKey, salt), kms(hmac(systemKey, password)))
```

### Storing A Password

1. `s = rand_bytes(32)`
2. `h = scrypt(password, salt, params)`
3. `eh = kms_encrypt(h)` 
4. `wk = scrypt(system_key, salt, params)`
5. `a = aes_ctr(wk, eh)`
6. `store(params, salt, a)`

### Verifying A Password

1. `params, salt, a = read(hash)`
2. `wk = scrypt(system_key, salt, params)`
3. `eh = aes_ctr(wk, a)`
4. `h = kms_decrypt(eh)`
5. `c = scrypt(possible_password, salt, params)`
6. `h == c`

## Threat Model

### Partial Local Breach

An attacker with only an offline copy of the authenticator hashes will be unable to re-derive `wk`
and thus unable to proceed.
 
### Total Local Breach

An attacker with an offline copy of the authenticator hashes and the system key will be able to
re-derive `wk` for each hash using the system key and the plaintext salt. They will be able to
decrypt the stored hashes and learn the KMS ciphertexts. Depending on the KMS format, this may
reveal the KMS key ID or other metadata. Lacking an authenticated context with the KMS, though, they
will be unable to decrypt the KMS ciphertexts and thus unable to proceed.

### Persistent Local Incursion

An attacker which establishes a persistent presence inside the trusted context will be able to make
requests to the KMS to decrypt and exfiltrate password hashes for offline attacks. The rate at which
they will be able to do so will be limited to the rate at which they can derive scrypt keys, and
their KMS operations will be visible via the KMS's audit log. (They will also be able to see user
passwords as users authenticate with the application.)

### Remote Breach

An attacker who is able to exfiltrate the keys managed by the KMS will be able to decrypt any KMS 
ciphertexts, but would have to brute-force the system key to obtain any.

### Persistent Remote Incursion

An attacker who is able to suborn the KMS will be able to mount DoS attacks, decrypt any KMS
ciphertexts in the future, alter the audit logs, and view any plaintexts sent to the KMS for
encryption. The only plaintexts they will see, however, will be scrypt hashes of user passwords
using an unknown salt. In order to mount a dictionary attack on the scrypt hashes, though, they will
first need to brute force the salt.

### Total Pwnage

An attacker who is able to suborn both the application context and the KMS context will be able to
mount dictionary attacks against the scrypt password hashes. Whatcha gonna do.