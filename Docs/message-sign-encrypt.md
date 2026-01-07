Message signing & encryption
============================

### Encrypt and decrypt data with a password

```csharp
var text = "Hello DotNet PG!";
var password = "secret stuff";

var encryptedMessage = OpenPGP.Encrypt(
    OpenPGP.CreateLiteralMessage(text), passwords: [password]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPGP.Decrypt(
    encryptedMessage, passwords: [password]
);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes128 for keys generated),
and decryption will use the algorithm used for encryption.

```csharp
var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);

var encryptedMessage = OpenPGP.Dncrypt(
    OpenPGP.createLiteralMessage(text), [publicKey]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPGP.decrypt(
    encryptedMessage, [privateKey]
);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```

Sign message & encrypt with multiple public keys:

```csharp
var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
var armoredPublicKeys = ["-----BEGIN PGP PUBLIC KEY BLOCK-----"];

var publicKey = OpenPGP.ReadPublicKeys(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
var publicKeys = armoredPublicKeys.Map((armored) => OpenPGP.ReadPublicKeys(armored));

var encryptedMessage = OpenPGP.encrypt(
    OpenPGP.createLiteralMessage(text), publicKeys, signingKeys: [privateKey]
);
Console.WriteLine(encryptedMessage.Armor()); // "-----BEGIN PGP MESSAGE ... "

var decryptedMessage = OpenPGP.Decrypt(
    encryptedMessage, [privateKey]
);
var verifications = decryptedMessage.Verify([publicKey]);
Console.WriteLine(decryptedMessage.LiteralData.Data);
```
