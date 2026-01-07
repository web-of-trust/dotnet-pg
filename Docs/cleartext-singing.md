Cleartext signing
=================

### Sign and verify cleartext
```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);

var signedMessage = OpenPGP.SignCleartext(text, [privateKey]);
var armored = signedMessage.Armor();
Console.WriteLine(armored);

verifications = OpenPGP.Verify(armored, [publicKey]);
```

### Detached sign and verify cleartext
```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPGP.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);

var signature = OpenPGP.SignDetachedCleartext(text, [privateKey]);
var armored = signature.Armor();
Console.WriteLine(armored);

var verifications = OpenPGP.VerifyDetached(text, armored, [publicKey]);
```
