---
layout: post
title: An Introduction to RSA
categories: linux
date: 2019-12-06
description: A walkthrough of the math behind RSA encryption and decryption
tags: [python, crypto]
katex: true
markup: "mmark"
---

# Public Key Cryptography

In public key cryptography, users generate a public and private keypair. The public key is used to encrypt a message and the private key is used to decrypt a message. The public key is meant to be shared with everyone and the private key is meant to be kept securely. **If the private key is ever compromised, all previous messages encrypted via the user's public key can be decrypted!**

## RSA

RSA (Rivest–Shamir–Adleman) is a widely adopted public-key cryptosystem. RSA is commonly used today as one of the cipher suites in Transport Layer Security (TLS). You'll typically find it used along [ECDHE](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) as the piece of cryptography that signs the exchange between your browser and the website you're connecting to.

> **Note**: All mathematical formulas in this post will be for Plain (also called "Textbook") RSA. Secure implementations of RSA include **padding** for which there is a section below. All python examples will be implemented securely.

### RSA Key Generation

RSA key generation is fairly simple. It's mostly multiplication and exponentiation. The whole basis of RSA keys is that choosing two numbers, $$p$$ and $$q$$, and multiplying them together is *very easy*, while trying to figure out what two numbers multiply together to form $$n$$ is *very hard*.

As a quick example, if I were to give you two prime numbers, $$7$$ and $$13$$, and asked you to multiply them, you'd figure out the answer quite fast. Now if I gave you the number $$91$$ and said, "What two prime numbers multiply together to create 91?", you would take considerably longer relative to the first scenario.

#### Mathematically

1. Choose two distinct prime numbers $$p$$ and $$q$$.
2. Compute $$n = pq$$.
3. Compute $$\lambda(n)$$, where $$\lambda$$ is [Carmichael's totient function](https://en.wikipedia.org/wiki/Carmichael%27s_totient_function).
 - This sounds complicated, but in theory it's just $$\lambda(n) = (p - 1) * (q - 1)$$
4. Choose an integer $$e$$ such that $$1 \lt e \lt \lambda(n)$$ and $$\gcd(e, \lambda(n)) = 1$$.
 - **This is *almost* always 3 (for less powerful devices) or 65,537.**
 - $$e$$ is the public key exponent.
5. Determine $$d$$ as $$d \equiv e^{-1} \pmod{\lambda(n)}$$
 - $$d$$ is the private key exponent. **$$(d)$$ is kept secret and never distributed.**$$\footnote{1}$$

The public key consists of $$n$$ and $$e$$. The private key consists of $$n$$ and $$d$$.

#### Python Implementation

With the [Cryptography](https://cryptography.io) library, you can skip all of the math and quickly generate secure RSA keypairs:

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

### Key Distribution

Suppose that Bob wants to send a message to Alice. Bob must first recieve Alice's public key to encrypt the message, and upon receipt, Alice will use her private key to decrypt the message. Alice will first send her public key $$(n, e)$$ to Bob via a reliable, but not necessarily secret route. Bob must be sure that he is getting Alice's key (and not an attacker's), but it is not a requirement that Alice's key must be hidden from anyone. **Alice's private key is never distributed.**

### RSA Encryption

Upon receipt of Alice's public key, Bob will turn his message into an integer $$m$$, such that $$0 \leq m \lt n$$. He then computes the ciphertext $$c$$ using Alice's public key $$e$$:

$$c \equiv m^e \pmod{n}$$

#### Padding

In order for a message to be securely converted into a ciphertext, it must be armored first. This armoring is more commonly referred to as padding which leads some to believe it is optional when [that couldn't be farther from the truth](https://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/). The most commonly used padding scheme is [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding). Before OAEP, RSA encryption with padding as described in PKCS#1v1.5 was used. [This has been known to be insecure](https://cryptosense.com/blog/why-pkcs1v1-5-encryption-should-be-put-out-of-our-misery/) since 1998 as described in Bleichenbacher's CRYPTO 98 paper called "[Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)".

##### Python Implementation

The following code uses the outdated Python library [PyCrypto](https://pypi.org/project/pycrypto/) and demonstrates an encryption and padding scheme that is vulnerable to the attack in Bleichenbacher's paper:

```Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

message = "Hello, world!"

key = RSA.generate(2048)
cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message.encode())
```

Similar to the other examples, the following secure code uses the Cryptography python package as well as the OAEP padding scheme:

```Python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

message = b"Attack at Dawn"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

### RSA Decryption

Upon receipt of the ciphertext, Alice can recover $$m$$ from $$c$$ by using her private key exponent $$d$$:

$$c^d \equiv (m^e)^d \equiv m \pmod n$$

##### Python Implementation

```Python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

### RSA Message Signing

RSA message signing solves the problem where Alice wants to send Bob a message, but Bob wants to be able to verify that Alice is the one who sent the message. Normally, anyone can get Bob's public key and send him the encrypted message, but Alice can verify that she meant the message by using her private key and a cryptographic hash function to sign the message. Bob can then take the signature and Alice's public key to verify that the sender of the message had to control Alice's private key.

Message signing is started by using a hash function on the message because the RSA operation can't handle messages longer than the modulus size. "[That means that if you have a 2048 bit RSA key, you would be unable to directly sign any messages longer than 256 bytes long (and even that would have problems, because of lack of padding)](https://crypto.stackexchange.com/a/9897/32614)".

#### Message Signing

1. Alice creates a hash of the message:
  - $$h = \text{hash}(m)$$
2. Alice raises it to the power of $$d ~ \text{mod} ~ n$$:
  - $$s = h^d \pmod n$$
3. Alice attaches $$s$$ to her message to Bob and sends it.

#### Message Verification

1. Bob receives the message and signature from Alice.
2. Bob creates a hash of the message using the same hashing algorithm as Alice:
  - $$h = \text{hash}(m)$$
3. Bob raises the signature to the power of $$e ~ \text{mod} ~ n$$:
  - $$h = s^e \pmod n$$
4. Bob then compares the resulting hash value with his calculated hash from step 2.
5. If the hashes match, then he knows that the sender had control of Alice's private key and the message has not been tampered with.

This process works because multiplication is commutative.

$$(h^e)^d = h^{ed} = h^{de} = (h^d)^e \equiv h \pmod n$$

#### Python Implementation

To sign a message:

```Python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

To verify the signature:

```Python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
except InvalidSignature:
    print("Signature is not valid!")
```

### Practical Attacks on Plain RSA

This section will detail a few of the attacks on Plain (Textbook) RSA. These are among the many very good reasons to always introduce padding into your RSA encryption/decryption routine.

#### Small Message Recovery

When $$e$$ is small and the message $$m$$ is such that $$m \lt n^{1/e}$$, then the encryption:

$$c = m^e \pmod n = m^{e}$$

has no modular reduction. A trivial recovery of the message involves computing $$\sqrt[e]{c}$$.

For example, let $$e = 3$$, $$m = 42$$, and $$n = 121411$$.

The ciphertext can be computed as: $$c = 42^3 \pmod{121411} = 42^{3} = 74088$$

The plaintext can then be recovered via: $$\sqrt[3]{c} = \sqrt[3]{74088} = 42 = m$$

#### Multiple Receiver Message Recovery

If the same message is encrypted, sent to $$e$$ or more recipients, and the receivers share the same exponent $$e$$, then it is easy to decrypt the original message using the [Chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).

For example, let $$e = 3$$.

Encrypting and sending a message $$m$$ to $$3$$ recipients yields:

$$c \equiv m^{3} \pmod{n_a}$$

$$c \equiv m^{3} \pmod{n_b}$$

$$c \equiv m^{3} \pmod{n_c}$$

The algorithm to find $$c$$ is:

$$c = c_a (n_b \cdot n_c) [ (n_b \cdot n_c)^{-1} ]_{n_a} + c_b (n_a \cdot n_c) [ (n_a \cdot n_c)^{-1} ]_{n_b} + c_c (n_a \cdot n_b) [ (n_a \cdot n_b)^{-1} ]_{n_c}$$

where $$[ a^{-1} ]_{b}$$ is the modular inverse of a and b.

With a message of $$m = 1337$$ and recipients of $$n_a = 3337, n_b = 3551, n_c = 3599$$:

$$c_a = 1337^{3} ~ \text{mod} ~ 3337 = 331$$

$$c_b = 1337^{3} ~ \text{mod} ~ 3551 = 509$$

$$c_c = 1337^{3} ~ \text{mod} ~ 3599 = 2620$$

We now have a set of congruences to solve for:

$$c \equiv 331 \pmod{3337}$$

$$c \equiv 509 \pmod{3551}$$

$$c \equiv 2620 \pmod{3599}$$

We can now use the equation for $$c$$ above:

$$t_a = c_a (n_b \cdot n_c) [ (n_b \cdot n_c)^{-1} ]_{n_a} = 331(3551 * 3599)[(3551 * 3599)^{-1}]_{3337} = 1324051416547$$

$$t_b = c_b (n_a \cdot n_c) [ (n_a \cdot n_c)^{-1} ]_{n_b} = 509(3337 * 3599)[(3337 * 3599)^{-1}]_{3551} = 10141500622953$$

$$t_c = c_c (n_a \cdot n_b) [ (n_a \cdot n_b)^{-1} ]_{n_c} = 2620(3337 * 3551)[(3337 * 3551)^{-1}]_{3599} = 49052964305200$$

$$\therefore c = t_a + t_b + t_c ~ \text{mod} ~ (n_a \cdot n_b \cdot n_c) = 2389979753$$

Computing for $$m$$, we get $$m = \sqrt[3]{c} = \sqrt[3]{2389979753} = 1337 = m$$

47\*71 = 3337, 53\*67 = 3551, 59\*61 = 3599

##### Python Implementation

```Python
m = 1337
e = 3
n_list = [3337, 3551, 3599]
n_combs = list(combinations(n_list, e-1))[::-1]

def eth_root(c, e):
    return round(abs(c) ** (1. / e))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# Generate Ciphertexts
cs = []
for i, n in enumerate(n_list):
    cs.append(m**e % n)

# Generate Equations
ts = []
for i, terms in enumerate(n_combs):
    eq_part1 = cs[i] * (terms[0] * terms[1])
    eq_part2 = modinv(terms[0] * terms[1], n_list[i])
    ts.append(eq_part1 * eq_part2)

# Recover the Message
c = sum(ts) % prod(n_list)
m = eth_root(c, e)
```

### Practical Attacks on RSA

#### General Number Field Sieves

The [general number field sieve](https://en.wikipedia.org/wiki/General_number_field_sieve) is the most efficient classical algorithm known for factoring integers larger than $$10^{100}$$. In 2009, a number field sieve was used to factor a 768-bit RSA number ($$n$$) in about 1500 years of computing time on current hardware. "[Factoring a 1024-bit RSA modulus would be about a thousand times harder](https://eprint.iacr.org/2010/006.pdf)". To date, this is the largest factored RSA number. With the rise of quantum computers on our horizon, Shor's Algorithm will be used in place of these classical methods.

#### Shor's Algorithm

[Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) is a quantum computer algorithm for integer factorization. In short, Shor's algorithm is almost exponentially faster than the most efficient known classical factoring algorithm, the general number field sieve. As noted in previous sections, the basis of RSA is the factorization problem, so an algorithm that greatly increases the ability to factor a number poses a threat to RSA.

I won't dive into Shor's algorithm in this post, but below is a video by MinutePhysics which contains an excellent walkthrough of it and the implications on current forms of cryptography.

{{< youtube lvTqbM5Dq4Q >}}

#### Bleichenbacher's RSA PKCS #1v1.5 Padding Oracle

Given an encrypted ciphertext and a padding oracle (a function whose input is a ciphertext and output reveals information about the padding), decrypt the ciphertext using a [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack).

For this challenge, I would recommend the cryptanalib from the Featherduster project by NCCGroup as it practically automates the entire attack for you. All you have to write is a padding oracle wrapper. I made a challenge based off of this attack which [you can read a writeup of here](https://github.com/CUCyber/cuctf-challenges/tree/master/solutions/cryptography/SMS).

```Python
import cryptanalib

def oracle(ciphertext):
   plaintext = key.decrypt(ciphertext)
   return plaintext.encode('hex')[:2] == '02'

plaintext = cryptanalib.bb98_padding_oracle(
    ciphertext,
    oracle,
    key.e,
    key.n,
    verbose=True,
    debug=True
)
```
