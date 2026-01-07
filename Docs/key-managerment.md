Key managerment
===============

### Generate new key pair

Rsa key type:
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
const string UserId = "Your name <name@example.com>";
var privateKey = OpenPGP.GenerateKey(
    [UserId],
    Passphrase,
    type: KeyType.Rsa,
    rsaKeySize: RSAKeySize.Normal,
);
Console.WriteLine(privateKey.Armor()); // "-----BEGIN PGP PRIVATE KEY BLOCK ... "
var publicKey = privateKey.Public;
Console.WriteLine(publicKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```

Ecc key type (uses EcDsa/EdDsaLegacy algorithm for signing & Ecdh algorithm for encryption):
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
const string UserId = "Your name <name@example.com>";
var privateKey = OpenPGP.GenerateKey(
    [UserId],
    Passphrase,
    type: KeyType.Ecc,
    curve: EcCurve.Secp521R1,
);
Console.WriteLine(privateKey.Armor()); // "-----BEGIN PGP PRIVATE KEY BLOCK ... "
var publicKey = privateKey.Public;
Console.WriteLine(publicKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```

Curve25519 key type (uses Ed25519 algorithm for signing & X25519 algorithm for encryption):
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
const string UserId = "Your name <name@example.com>";
var privateKey = OpenPGP.GenerateKey(
    [UserId],
    Passphrase,
    type: KeyType.Curve25519,
);
Console.WriteLine(privateKey.Armor()); // "-----BEGIN PGP PRIVATE KEY BLOCK ... "
var publicKey = privateKey.Public;
Console.WriteLine(publicKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```

Curve448 key type (uses Ed448 algorithm for signing & X448 algorithm for encryption):
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
const string UserId = "Your name <name@example.com>";
var privateKey = OpenPGP.GenerateKey(
    [UserId],
    Passphrase,
    type: KeyType.Curve448,
);
Console.WriteLine(privateKey.Armor()); // "-----BEGIN PGP PRIVATE KEY BLOCK ... "
var publicKey = privateKey.Public;
Console.WriteLine(publicKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```

### Key reading

Key reading from armored key strings
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, Passphrase);
```

### Certify a key

Certify a key by using the private key:
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
vararmoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, Passphrase);

var certifiedKey = privateKey.CertifyKey(publicKey);
certifiedKey.IsCertified(privateKey.Public);
Console.WriteLine(certifiedKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```

### Revoke a key

Revoke a key by using the private key:
```csharp
using DotNetPG;

const string Passphrase = "Your passphase";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, Passphrase);

var revokedKey = privateKey.RevokeKey(publicKey);
revokedKey.isRevoked(privateKey.Public);
Console.WriteLine(revokedKey.Armor()); // "-----BEGIN PGP PUBLIC KEY BLOCK ... "
```
