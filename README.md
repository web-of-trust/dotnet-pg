DotNet PG - The OpenPGP library in .NET
=================================================
DotNet PG is an implementation of the OpenPGP standard in .NET.
It implements [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) and
provides encryption with public key or symmetric cryptographic algorithms,
digital signatures, compression, and key management.

## Requirement
* .NET 9.x or later.
* [BouncyCastle.NET](https://www.bouncycastle.org/csharp) library provides cryptography algorithms.

## Features
* Support data signing & encryption.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: [RSA](https://www.rfc-editor.org/rfc/rfc3447),
  [ECDSA](https://www.rfc-editor.org/rfc/rfc6979),
  [EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
* Support symmetric ciphers: Blowfish, Twofish,
  [AES](https://www.rfc-editor.org/rfc/rfc3394),
  [Camellia](https://www.rfc-editor.org/rfc/rfc3713).
* Support AEAD ciphers: [EAX](https://seclab.cs.ucdavis.edu/papers/eax.pdf),
  [OCB](https://tools.ietf.org/html/rfc7253),
  [GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf).
* Support hash algorithms: SHA-256, SHA-384, SHA-512, SHA-224, SHA3-256, SHA3-512.
* Support compression algorithms: Zip, Zlib, BZip2.
* Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secp256r1, secp384r1, secp521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [Curve25519, Curve448](https://www.rfc-editor.org/rfc/rfc7748),
  [Ed25519, Ed448](https://www.rfc-editor.org/rfc/rfc8032).
* Support symmetric ciphers & hash algorithms for message decryption
  (backward compatibility): TripleDES, IDEA, CAST5, MD5, SHA-1, RIPEMD-160.

## Installation

## Basic usage of DotNet PG
Sign and verify cleartext message
~~~csharp
using DotNetPG;

var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
var passphrase = "Your passphrase";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
var cleartextMessage = OpenPGP.CreateCleartextMessage("Hello, DotNet PG!");
var signedMessage = cleartextMessage.Sign([privateKey]);
var verifications = signedMessage.Verify([publicKey]);
~~~
## Licensing
[BSD 3-Clause](LICENSE)

    For the full copyright and license information, please view the LICENSE
    file that was distributed with this source code.
