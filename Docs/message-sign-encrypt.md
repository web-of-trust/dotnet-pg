Message signing & encryption
============================

### Encrypt and decrypt data with a password

```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var password = "secret stuff";

var encryptedMessage = OpenPgp.Encrypt(
    OpenPgp.CreateLiteralMessage(text), passwords: [password]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPgp.Decrypt(
    encryptedMessage, passwords: [password]
);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes128 for keys generated),
and decryption will use the algorithm used for encryption.

```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPgp.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPgp.DecryptPrivateKey(armoredPrivateKey, passphrase);

var encryptedMessage = OpenPgp.Dncrypt(
    OpenPgp.createLiteralMessage(text), [publicKey]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPgp.decrypt(
    encryptedMessage, [privateKey]
);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```

Sign message & encrypt with multiple public keys:

```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
var armoredPublicKeys = ["-----BEGIN PGP PUBLIC KEY BLOCK-----"];

var publicKey = OpenPgp.ReadPublicKeys(armoredPublicKey);
var privateKey = OpenPgp.DecryptPrivateKey(armoredPrivateKey, passphrase);
var publicKeys = armoredPublicKeys.Map((armored) => OpenPgp.ReadPublicKeys(armored));

var encryptedMessage = OpenPgp.encrypt(
    OpenPgp.createLiteralMessage(text), publicKeys, signingKeys: [privateKey]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPgp.Decrypt(
    encryptedMessage, [privateKey]
);
var verifications = decryptedMessage.Verify([publicKey]);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```
