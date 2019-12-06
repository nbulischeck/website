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


### RSA Key Generation

RSA key generation is fairly simple. It's mostly multiplication and exponentiation. The whole basis of RSA keys is that choosing two numbers, $$p$$ and $$q$$, and multiplying them together is *very easy*, while trying to figure out what two numbers multiply together to form $$n$$ is *very hard*.

As a quick example, if I were to give you two prime numbers, $$7$$ and $$13$$, and asked you to multiply them, you'd figure out the answer quite fast. Now if I gave you the number $$91$$ and said, "What two prime numbers multiply together to create 91?", you would take considerably longer relative to the first scenario.

#### Mathematically

1. Choose two distinct prime numbers $$p$$ and $$q$$.
2. Compute $$n = pq$$.
3. Compute $$\lambda(n)$$, where $$\lambda$$ is [Carmichael's totient function](https://en.wikipedia.org/wiki/Carmichael%27s_totient_function).
 - This sounds complicated, but in theory it's just $$\lambda(n) = (p - 1) * (q - 1)$$
4. Choose an integer $$e$$ such that $$1 \lt e \lt \lambda(n)$$.
 - This is almost always 3 (for less powerful devices) or, more generally, 65,537.
5. Determine $$d$$ as $$d \equiv e^{-1} \pmod{\lambda(n)}$$
 - $$d$$ is kept secret as the private key exponent.

#### In Python

With the PyCrypto library, you can skip all of the math and generate secure RSA keypairs.

```python
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
```

### Key Distribution

Suppose that Bob wants to send a message to Alice. Bob must first recieve Alice's public key to encrypt the message, and upon receipt, Alice will use her private key to decrypt the message. Alice will first send her public key $$(n, e)$$ to Bob via a reliable, but not necessarily secret route. Bob must be sure that he is getting Alice's key (and not an attacker's), but it is not a requirement that Alice's key must be hidden from anyone. **Alice's private key $$(d)$$ is never distributed.**

### RSA Encryption

Upon receipt of Alice's public key, Bob will turn his message into an integer $$m$$, such that $$0 \leq m \lt n$$. He then computes the ciphertext $$c$$ using Alice's public key $$e$$:

$$c \equiv m^e \pmod{n}$$

### RSA Decryption

Upon receipt of the ciphertext, Alice can recove $$m$$ from $$c$$ by using her private key exponent $$d$$:

$$c^d \equiv (m^e)^d \equiv m \pmod n$$

### Breaking RSA

1. Find `n` and `e` from the public key
2. Factor `n` into `p` and `q`
3. Calculate `d` with `e`, `p`, and `q`
4. Generate a private key
5. Decrypt the ciphertext with our new private key

Recall that `n` and `e` are meant to be shared with everyone and that in no way is this information supposed to be considered a secret. To recover `n` and `e`, we can use a simple Python program.

```python
from Crypto.PublicKey import RSA

f = open("public.key", "r")
key = RSA.importKey(f.read())
print(key.n, key.e)
```

This prints the following:

```
n = 90187489204964341357580822098641855317607686795656773417285864916432620562501
e = 65537
```

1. ~~Find `n` and `e` from the public key~~
2. Factor `n` into `p` and `q`
3. Calculate `d` with `e`, `p`, and `q`
4. Generate a private key
5. Decrypt the ciphertext with our new private key

Recall that recovering the private key all hinges on being able to factor `n`. This means that we need a sufficiently **small** `n` that we can factor into `p` and `q`. A very good tool for doing this is `Yafu` or Yet Another Factoring Utility.

If we just launch `yafu` and run the `factor` command with our `n`, `yafu` will attempt to factor it and lucky for us, after only 114.6398 seconds or a little under 2 minutes we were able to recover `p` and `q`.

```
p = 324388787784871038939401053607215918019
q = 278022831247715948169664169460326581079
```

1. ~~Find `n` and `e` from the public key~~
2. ~~Factor `n` into `p` and `q`~~
3. Calculate `d` with `e`, `p`, and `q`
4. Generate a private key
5. Decrypt the ciphertext with our new private key

Now that we've recovered `p` and `q`, we can move on to calculating `d`. To do this, I wrote a simple python program that implements the formula for calculating `d`. I used the `ECDSA` module to import the `inverse_mod` function so that we don't have to implement it ourselves. If you want to implement this function yourself you can take a look over at [this math stackexchange post](<https://math.stackexchange.com/questions/25390/how-to-find-the-inverse-modulo-m>).

```python
from ecdsa.numbertheory import inverse_mod

e = 65537
p = 324388787784871038939401053607215918019
q = 278022831247715948169664169460326581079
d = inverse_mod(e, ((p-1) * (q-1)))
print(d)
```

```
d = 34163825121724289157930657329766127532538458604069030506669045412324052489465
```

1. ~~Find `n` and `e` from the public key~~
2. ~~Factor `n` into `p` and `q`~~
3. ~~Calculate `d` with `e`, `p`, and `q`~~
4. Generate a private key
5. Decrypt the ciphertext with our new private key

To generate a private key, we can write some more python that turns out to be very simple.

```python
from Crypto.PublicKey import RSA

n = 90187489204964341357580822098641855317607686795656773417285864916432620562501
e = 65537
d = 34163825121724289157930657329766127532538458604069030506669045412324052489465
p = 324388787784871038939401053607215918019
q = 278022831247715948169664169460326581079

key_params = (n, e, d, p, q)
key = RSA.construct(key_params)
print(key.exportKey().decode('utf-8'))
```

If we run the above python, it outputs our desired RSA private key.

{% include image.html path="BSCHS/rsapcap/private-key-generated.png" path-detail="BSCHS/rsapcap/private-key-generated.png" alt="Private Key Generated" %}

1. ~~Find `n` and `e` from the public key~~
2. ~~Factor `n` into `p` and `q`~~
3. ~~Calculate `d` with `e`, `p`, and `q`~~
4. ~~Generate a private key~~
5. Decrypt the ciphertext with our new private key

Lastly all we have to do is decrypt the ciphertext given the private key that we just generated. Fortunately for us, this is as easy as a single openssl command.

`openssl rsautl -decrypt -inkey mykey.priv -in secret`

This was worth an astounding 750 points! I hope you enjoyed the long explanation of how to solve this, but here is where I might make you a little mad. There is a tool on Github called [RSACtfTool](<https://github.com/Ganapati/RsaCtfTool>) that does everything for you in just a couple seconds. No need to understand RSA or the attacks on it. No complicated math, just input and run.

All we have to do is supply `RSACtfTool.py` with the public key and ciphertext and it attempts to generate the private key and decipher the ciphertext.

There isn't a need to reinvent the wheel, but understanding how this magic tool works is beneficial.
