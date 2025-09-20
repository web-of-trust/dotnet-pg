using DotNetPG.Common;
using DotNetPG.Enum;
using DotNetPG.Packet;
using Org.BouncyCastle.Utilities.Encoders;

namespace Test.Packet;

public class SecretKeyTest
{
    private const string Passphrase = "password";

    [Test]
    public void TestRsaSecretKey()
    {
        const string keyData = @"BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAH+BwMCLQGcMzPKel7/nlml
LznQdMJ5SimdfqT4NvlNkb5QN+IqXfqOg01EF0cbWsT510j8iAox1auK9lJstyeqKK1ttqdF/2wf
dymZ0UQn+BqqvYqACMQmBhXvi/jr4m+4AJC3PLwIapLZaQS/HT+sqqU2WheSCUD2v4pA069B0jGL
nQ8t+j1dJrentK/hr6S/q06G/gOehcRKPYnTjM2lDv8TUA7Yg45dYwRKRg3IneQor2Yh2d0tvL78
U4Dq1YMFfgvsO4szknklq4sQGKLH4DRv+Cv+sALZOFTNv0h851tLP+22RnwfKUbQ9F9uw0MG9Rav
7Wy+ililDQXcU1kYMMIU8vBbGmwjwRrP7QM1NbmGrOEpdDZKgAUWnyv+EtMPxfytbFcj8rF2yAf5
xd3lrQdQcR8ePxE8dbbV/c1KwkbKDfXAQOSoEFJpFNqXEAK9he59oKICH+4yMqXxIXYDaMognhtP
hH/tZCgYRzLavt9dR6BJ9VGhgzNgtWsvn+5L4oBfDBF2XjB3mKLMdjvO9wH1SLLRaAtIx2xGdT1c
ediMVFo5uNdDC97CQwAx4QDlX5RbQHe7lq0T7t2WQ8LagjciTeDOtKEf5WN69a1kGSzgJn6rm1GL
fCc93clNyiYygS+GaVFnhr/hEdq8pRiIUs7FlpK9lPNMv9Ecs03fGE0ZzA3gWyb1KZLpwFLXk2XR
BM8cDkFsIy9Mn9e9p85IcXZ3WDuJms/gkYRb1CsVTsvVSft1+xYi/Ve6JmIeRkE1weRLuOMkqvFJ
QdjujszGY2uSv1iTik/46DAEf0yJ7/7Fwt9gSgTLEbh0NIGE21Z11BKY+ovITfgrmJOhP9kQ6oIX
RfZglUaCOkOPtqPMQNOpZiV3VY6IOay+r7y9Rx2xT03WrnSowNZQXSCksonthXUZAXoGSeFO";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("fc5004df9473277107eaa605184d0dc4f5c532b2")));
            Assert.That(secretKey.KeyId, Is.EqualTo(Hex.Decode("184d0dc4f5c532b2")));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestRsaSecretSubkey()
    {
        const string keyData = @"BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
MHBMlyq+QLfPuvPg187E0nsi1fh+P6sJ+gjNjSibyDdsBjHW6ZDksoB7lO5NhSCnzo63kMlP7QBH
hvOWaZSUHG3JqCsdElDSHkMrHpVzpyco+bTs7XK/E1iS0kC32yE7ShV/rltvl8hUKZF1npG3ytka
fegaEYESkM32/vygrCOWNC1Tea7kWe1A0+/ZYbgPh3blorNGICkUqiKfST9Xq26Lb67Kc38Gxjij
X9LAnOoxEyCjmCv/+ajNIDvMSQOtnTCapLpRrhLlzjvIDtOnABEBAAH+BwMCU66+g6RWISb/kIpn
DK3Sgc4XmiVF8NV0MS5rjxbZgBwrs61dCB2t2wV/evGZ1sUN1EOSleOG8z8J1lUZoz3DKzfUf5st
uVIm4c5P6U/0raU9JQpGid1kONDR3qeLDetCPcCEVsn7EXpxNccgRLkwUWCHm4ipwg+2mJlaTjsQ
v0GPnOxfV5coFoMZw1XkeroSzD/7Le9W5gx32FWbjSFpOZkRAbdqux+sD+u8jmGV84k42TZninew
JQz3XC7H9JljKPW5+dCenJBM56Vlef0fGq9SRXCpJoLGhdNh1JlFPt/3VAhzJYPAwzDz1ThpVRHF
Thq/9dMhMg2FJnOETIsty0i60rPeppbDauB67p+KVfqtX7u99gPYgpE/qRHPQN3IKo1G1bCrXBYJ
q1Ot8pzyJDZVf8qOk6I7ZmYVg27pZeReYgwnDkMpRJMn8w2/8sIKNAJ1BKX1pogNrWuLOpOioEx/
iZnn1BTqYTMneovgx758AkAvmcWh1i9qUygQlS9Jo/LHyoGAs06ywwQoqmf5dRCObOwW9fXEVnKw
lg1mVN65ZRyCql6FRcw+nicgijTwhRkVu4vfyTjKyLxEG6umRqVT7zDxoEd3KzA5JtFC2HUPcB7M
t75BqE0PoPSYfdKkWdqiCHbRHY+5Z6Wzv8jw2+lY+epd4IZEFe0r9AckCnjmPT1iln+RPCFWeuSS
HAL5kl+bvXSsfDmiqM9g7i36mtAe5zL9ZJ/A1Af4gOLq2YGVJTvDIr93V8es2XG0yngl5+/o8x8o
o630OHhhneEQ7blqGQKnBdrXtFKTVwGXA8EkCwgl4IK5OJrs9W+SkwBgfhxDCHprfFyH1ARSzjK1
TBGwJ0VVxJEtKxd0eQnmvNDYdo2kbGriXFcTyCzMGz/KKfqlsu3kPf/NCNgr+zxx8Z+xyDtG";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("42badbbe0f2acabacd6cac7c4be1b3a621ef906f")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("4be1b3a621ef906f")));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEcDsaP384SecretKey()
    {
        const string keyData = @"BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh/gcD
AjbYiI4QU+mo/woxqTXpIZE1wzaaNJ5+iRA7vvc6rdJZSjQUkXTJ3/zOyI4970a4UDTJ948+jiUt
aJrhbMr17UySI58IyBvTxA3hFy63JRJWy5dhJU7kQ3PljGTlqOGB";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("05c085492d14f90976e7c2b6b202d9e2eada440c")));
            Assert.That(secretKey.KeyId, Is.EqualTo(Hex.Decode("b202d9e2eada440c")));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEcDhP384SecretSubkey()
    {
        const string keyData = @"BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
Cf4HAwIcyJh6Un3tq/+P7HrG3HYoS3MBHwEHsYbsogsXCJyutYSZ3yn4Fuyk8FJnH9GGDJatBxkp
HjhNl+M7wpWyEyjh9WWJHFrC7Zgbx1RZbFHtM/aCtvqUQHqGwiR7uY9b0w==";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("c0b7b9c6bf5824b6")));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEcDsaBrainpoolP256SecretKey()
    {
        var keyData = @"BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrT+BwMCfKl8O5GIbj3/eruMvK1KnzWCGiQutGTYgQmP
u5aHJEwxtiXZFAHUTxoHgr3yd0IewonQL4Xxz25Zmp1iNL2VSyfPE5v8EDwgWcxCT9m1pQ==";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("06fee3085d46dc007c0ec2f01cbcd043db44c5d6")));
            Assert.That(secretKey.KeyId, Is.EqualTo(Hex.Decode("1cbcd043db44c5d6")));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEcDhPrainpoolP256SecretSubkey()
    {
        var keyData = @"BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH/gcDApz0MLgF17Br/2e17kAJ360GEHYrfgn6
dstKPfglOcNKt8PdckwiF6g8gGm3WSPKU/7MkR2C+lKMOJWFxY0G9U77H35I+Vv9W9828ybAmxM=";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("457b5979545fba09be179db808a55bdb1d673d5d")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("08a55bdb1d673d5d")));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEdDsaLegacyCurve25519SecretKey()
    {
        var keyData = @"BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM/gcDAg3L
LOtx/PSU/9E+PgO1Rd79U+hHRifxAcg+kLq3aoLBbA7RmrVdDTeQvoFl3C+WCC1WleUW21FsUpce
31nuheiWbgVEXVXQUOcXaVbGVGY=";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("1c4116eb2b58cfa196c57ddbbdff135160c56a0b")));
            Assert.That(secretKey.KeyId, Is.EqualTo(Hex.Decode("bdff135160c56a0b")));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestEcDhCurve25519SecretSubkey()
    {
        var keyData = @"BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAf+
BwMCXhynxjWHX9z//fP2s+xS5iJ1GuvkHqAq+i32Z7LO/92WrWb521yGgPfAipIfrwxwgLZByGjg
DE1hLVYK35eygNH+dtRvaK5/hLCNXKeUiQ==";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("8efa53a375fc569aa9ca564a044eac93f0b69ea0")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("044eac93f0b69ea0")));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestCurve25519Version6SecretKey()
    {
        var keyData = "BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWjABlygXsSvnB+jV9YbOYTYSAdNE6yZqLIL95oNXYrZbC3Dac=";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestCurve25519Version6SecretSubkey()
    {
        var keyData = "BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24EL4=";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });
    }

    [Test]
    public void TestLockedCurve25519Version6SecretKey()
    {
        const string passphrase = "correct horse battery staple";
        var keyData = @"BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj/SYJAhQEXW/XHJ4JbR62
kXtubh7srgEEFbSoqSdPq+Yy+HWnBlkgIXglj6SE2Isn8iDj0t4CA8oPH+7La3dTgePi2bFIXCIz
jKVR4JomPyLrSZLpZ3qAWA==";

        var secretKey = SecretKey.FromBytes(Base64.Decode(keyData)).Decrypt(passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var s2k = secretKey.S2k;
        var derivedKey = s2k.ProduceKey(passphrase, (Helper.SymmetricKeySize(secretKey.Symmetric) + 7) >> 3);
        Assert.That(Hex.ToHexString(derivedKey), Is.EqualTo("832bd2662a5c2b251ee3fc82aec349a766ca539015880133002e5a21960b3bcf"));
    }

    [Test]
    public void TestLockedCurve25519Version6SecretSubkey()
    {
        const string passphrase = "correct horse battery staple";
        var keyData = @"BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1/SYJAhQEDmGEaCnahpq+
DqYVRdwUzAEEFS4Typ/05yT7HC6x34YCCUGvktXKv+W6nfHFC8dcVKOMDaFpd+g3rFQZF0MQcjr6
568qNVG/mgDGC7t4mlpc2A==";
        
        var subkey = SecretSubkey.FromBytes(Base64.Decode(keyData)).Decrypt(passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var s2k = subkey.S2k;
        var derivedKey = s2k.ProduceKey(passphrase, (Helper.SymmetricKeySize(subkey.Symmetric) + 7) >> 3);
        Assert.That(Hex.ToHexString(derivedKey), Is.EqualTo("f74a6ce873a089ef13a3da9ac059777bb22340d15eaa6c9dc0f8ef09035c67cd"));
    }

    [Test]
    public void TestGenerateRsaSecretKey()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.RsaGeneral);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(2048));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEcDsaSecretKeySecp521R1()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDsa, curve: EcCurve.Secp521R1);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(521));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEcDsaSecretKeyBrainpoolP512R1()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDsa, curve: EcCurve.BrainpoolP512R1);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(512));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEdDsaLegacySecretKeyEd25519()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EdDsaLegacy, curve: EcCurve.Ed25519);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(255));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EdDsaLegacy));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEcDhSecretKeySecp521R1()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDh, curve: EcCurve.Secp521R1);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(521));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEcDhSecretKeyBrainpoolP512R1()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDh, curve: EcCurve.BrainpoolP512R1);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(512));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEcDhSecretKeyCurve25519()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDh, curve: EcCurve.Curve25519);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(255));
            Assert.That(secretKey.Version, Is.EqualTo(4));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateV6RsaKey()
    {
        Config.PresetRfc = PresetRfc.Rfc9580;
        var secretKey = SecretKey.Generate(KeyAlgorithm.RsaGeneral);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(2048));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, aead: AeadAlgorithm.Ocb);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(AeadAlgorithm.Ocb));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
        Config.PresetRfc = PresetRfc.Rfc4880;
    }

    [Test]
    public void TestGenerateV6EcDsaKey()
    {
        Config.PresetRfc = PresetRfc.Rfc9580;
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDsa);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(521));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, aead: AeadAlgorithm.Gcm);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(AeadAlgorithm.Gcm));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
        Config.PresetRfc = PresetRfc.Rfc4880;
    }

    [Test]
    public void TestGenerateV6EcDhKey()
    {
        Config.PresetRfc = PresetRfc.Rfc9580;
        var secretKey = SecretKey.Generate(KeyAlgorithm.EcDh);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(521));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, aead: Config.PreferredAead);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(Config.PreferredAead));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
        Config.PresetRfc = PresetRfc.Rfc4880;
    }

    [Test]
    public void TestGenerateX25519Key()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.X25519);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(255));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, Config.PreferredSymmetric, Config.PreferredAead);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(Config.PreferredAead));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateX448Key()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.X448);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(448));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X448));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, Config.PreferredSymmetric, Config.PreferredAead);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(Config.PreferredAead));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEd25519Key()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.Ed25519);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(255));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, Config.PreferredSymmetric, Config.PreferredAead);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(Config.PreferredAead));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEd448Key()
    {
        var secretKey = SecretKey.Generate(KeyAlgorithm.Ed448);
        Assert.Multiple(() =>
        {
            Assert.That(secretKey.IsEncrypted, Is.False);
            Assert.That(secretKey.KeyLength, Is.EqualTo(448));
            Assert.That(secretKey.Version, Is.EqualTo(6));
            Assert.That(secretKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed448));
            Assert.That(secretKey.SecretKeyMaterial!.IsValid(), Is.True);
        });

        var encryptedSecretKey = secretKey.Encrypt(Passphrase, Config.PreferredSymmetric, Config.PreferredAead);
        Assert.That(encryptedSecretKey.IsEncrypted, Is.True);
        Assert.That(encryptedSecretKey.Aead, Is.EqualTo(Config.PreferredAead));

        var decryptedSecretKey = SecretKey.FromBytes(encryptedSecretKey.ToBytes()).Decrypt(Passphrase);
        Assert.That(secretKey.Fingerprint, Is.EqualTo(decryptedSecretKey.Fingerprint));
    }
}
