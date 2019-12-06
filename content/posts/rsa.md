---
layout: post
title: An Introduction to RSA
categories: linux
date: 2019-12-06
description: A walkthrough of the math behind RSA encryption and decryption
tags: [python, crypto]
---

In order to understand why this next part works, we need to understand a little about the method used to encrypt the message. In public key cryptography, users generate a public and private keypair. The public key is used to encrypt a message and the private key is used to decrypt a message. The public key is meant to be shared with everyone that intends on encrypting a message and sending it to the owner of the public key. The private key is meant to be kept securely by whoever generated the public and private keypair.

{% include image.html path="BSCHS/rsapcap/public-key-encryption.png" path-detail="BSCHS/rsapcap/public-key-encryption.png" alt="Public Key Crypto" %}

For example, Alice sends Bob her public key. Remember, this is not intended to be a secret. Bob then encrypts his message, "Hello Alice!", with Alice's public key. At this point, the ciphertext that Bob generated by encrypting his message with Alice's public key is essentially invulnerable. The ciphertext is then sent to Alice. Alice is able to decrypt the ciphertext with the private key that corresponds with the public key Bob used.

Therefore, if you are able to retrieve a user's private key, you're able to decrypt any message that they have received if it was encrypted with their public key.

In order to understand how we can break RSA, we need to understand a little about the math behind it. The public key is made up of two variables, `n` and `e`. `n` is a very large number designed to be made public to everyone. `e` is almost always 65537. The private key is made up of five variables, `n`, `e`, `d`, `p`, and `q`. The `n` and `e` come from the public key. We know `e` is almost always 65537 to comply with the standard, but where does `n` come from? The variable `n` comes from the equation `n = p * q`. Both `p` and `q` are very large random prime numbers. RSA is based on the fact that multiplying `p` and `q` together is very computationally easy, but figuring out what two numbers make an integer `n` is **very** computationally difficult. Lastly, `d` is the exponent used to decrypt the ciphertext. `d` can be found with the equation `d = modinv(e, ((p-1) * (q-1))` where `modinv` is the modular inverse function.

Let's clarify our objectives now:

1. Find `n` and `e` from the public key
1. Factor `n` into `p` and `q`
1. Calculate `d` with `e`, `p`, and `q`
1. Generate a private key
1. Decrypt the ciphertext with our new private key

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
1. Factor `n` into `p` and `q`
1. Calculate `d` with `e`, `p`, and `q`
1. Generate a private key
1. Decrypt the ciphertext with our new private key

Recall that recovering the private key all hinges on being able to factor `n`. This means that we need a sufficiently **small** `n` that we can factor into `p` and `q`. A very good tool for doing this is `Yafu` or Yet Another Factoring Utility.

If we just launch `yafu` and run the `factor` command with our `n`, `yafu` will attempt to factor it and lucky for us, after only 114.6398 seconds or a little under 2 minutes we were able to recover `p` and `q`.

{% include image.html path="BSCHS/rsapcap/yafu-cracked.png" path-detail="BSCHS/rsapcap/yafu-cracked.png" alt="YAFU Cracked" %}

```
p = 324388787784871038939401053607215918019
q = 278022831247715948169664169460326581079
```

1. ~~Find `n` and `e` from the public key~~
1. ~~Factor `n` into `p` and `q`~~
1. Calculate `d` with `e`, `p`, and `q`
1. Generate a private key
1. Decrypt the ciphertext with our new private key

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
1. ~~Factor `n` into `p` and `q`~~
1. ~~Calculate `d` with `e`, `p`, and `q`~~
1. Generate a private key
1. Decrypt the ciphertext with our new private key

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
1. ~~Factor `n` into `p` and `q`~~
1. ~~Calculate `d` with `e`, `p`, and `q`~~
1. ~~Generate a private key~~
1. Decrypt the ciphertext with our new private key

Lastly all we have to do is decrypt the ciphertext given the private key that we just generated. Fortunately for us, this is as easy as a single openssl command.

`openssl rsautl -decrypt -inkey mykey.priv -in secret`

{% include image.html path="BSCHS/rsapcap/decrypted.png" path-detail="BSCHS/rsapcap/decrypted.png" alt="Decrypted" %}

This was worth an astounding 750 points! I hope you enjoyed the long explanation of how to solve this, but here is where I might make you a little mad. There is a tool on Github called [RSACtfTool](<https://github.com/Ganapati/RsaCtfTool>) that does everything for you in just a couple seconds. No need to understand RSA or the attacks on it. No complicated math, just input and run.

All we have to do is supply `RSACtfTool.py` with the public key and ciphertext and it attempts to generate the private key and decipher the ciphertext.

{% include image.html path="BSCHS/rsapcap/rsa-solve.png" path-detail="BSCHS/rsapcap/rsa-solve.png" alt="RSA Solved" %}

There isn't a need to reinvent the wheel, but understanding how this magic tool works is beneficial.