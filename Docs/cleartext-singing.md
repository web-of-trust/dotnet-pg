Cleartext signing
=================

### Sign and verify cleartext
```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPgp.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPgp.DecryptPrivateKey(armoredPrivateKey, passphrase);

var signedMessage = OpenPgp.SignCleartext(text, [privateKey]);
var armored = signedMessage.Armor();
Console.WriteLine(armored);

verifications = OpenPgp.Verify(armored, [publicKey]);
```

### Detached sign and verify cleartext
```csharp
using DotNetPG;

var text = "Hello DotNet PG!";
var passphrase = "secret stuff";
var armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
var armoredPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

var publicKey = OpenPgp.ReadPublicKey(armoredPublicKey);
var privateKey = OpenPgp.DecryptPrivateKey(armoredPrivateKey, passphrase);

var signature = OpenPgp.SignDetachedCleartext(text, [privateKey]);
var armored = signature.Armor();
Console.WriteLine(armored);

var verifications = OpenPgp.VerifyDetached(text, armored, [publicKey]);
```
