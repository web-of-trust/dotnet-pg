using DotNetPG.Enum;
using DotNetPG.Packet;
using DotNetPG.Packet.Key;
using Org.BouncyCastle.Utilities.Encoders;

namespace Test.Packet;

public class PKESKTest
{
    private const string Passphrase = "password";
    private const string LiteralText = "Hello, world!";

    private const string RsaSecretSubkey = @"BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
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

    private const string EcdhP384SecretSubkey = @"BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
Cf4HAwIcyJh6Un3tq/+P7HrG3HYoS3MBHwEHsYbsogsXCJyutYSZ3yn4Fuyk8FJnH9GGDJatBxkp
HjhNl+M7wpWyEyjh9WWJHFrC7Zgbx1RZbFHtM/aCtvqUQHqGwiR7uY9b0w==";

    private const string EcdhBrainpoolSecretSubkey = @"BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH/gcDApz0MLgF17Br/2e17kAJ360GEHYrfgn6
dstKPfglOcNKt8PdckwiF6g8gGm3WSPKU/7MkR2C+lKMOJWFxY0G9U77H35I+Vv9W9828ybAmxM=";

    private const string EcdhCurve25519SecretSubkey = @"BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAf+
BwMCXhynxjWHX9z//fP2s+xS5iJ1GuvkHqAq+i32Z7LO/92WrWb521yGgPfAipIfrwxwgLZByGjg
DE1hLVYK35eygNH+dtRvaK5/hLCNXKeUiQ==";
    
    [Test]
    public void TestDecryptRsaSessionKey()
    {
        var data = @"hQEMA0vhs6Yh75BvAQf/d3sy2mx7mDExsPErVN7Dksswz0GErXcsWswsjI/GOFOA
DnEFyniJBGYJaL/kjv1fOqOlW0E4+9PZFxl7vg6bjjE7RiNgCIN5SMPp2G3w4KaT
a3emPFjRn9SanxTZCsrfGDHEdXxOjViersve2FRD7DniOpLLcZj3s5Q4MfD7UF6M
oWGnhynDYFETLS/D0j1ehm/2+0ZOr5xNxLLE0gLxYopg99is7kgE9ppAcbaJ7ixD
kKElBrxKOk3TdYJO0WbQ90UrNPt40fxFfSGXO3fdXE0ds4aRoUEzW3KRjamuMkux
danLSEjbCHUgDTj47/ly0/63N0/zzrgKIUES4LUzh9RIAQkCEFInanBKOrcss7wr
zRWdZZNnYoIwe96fREBcpXqxKvnIKm5/hjA4T2RMG5SnHKHCzkT9sEKSq/cLEQ6a
JnzOL3WiY9Ln";

        var packets = PacketList.Decode(Base64.Decode(data));
        var subkey = SecretSubkey.FromBytes(Base64.Decode(RsaSecretSubkey)).Decrypt(Passphrase);
        var pkesk = (PublicKeyEncryptedSessionKey)packets[0];
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));
        Assert.That(pkesk.SessionKey, Is.Null);

        var decryptedpPkesk = pkesk.Decrypt(subkey);
        Assert.That(decryptedpPkesk.SessionKey, Is.Not.Null);
    }

    [Test]
    public void TestEncryptRsaSessionKey()
    {
        var sessionKey = SessionKey.ProduceKey();
        var subkey = SecretSubkey.FromBytes(Base64.Decode(RsaSecretSubkey)).Decrypt(Passphrase);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, subkey.PublicKey);
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));

        var packets =  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(subkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
        Assert.That(sessionKey.Symmetric, Is.EqualTo(decryptedPkesk.SessionKey!.Symmetric));
    }

    [Test]
    public void TestDecryptEcDhP384SessionKey()
    {
        var data = @"hJ4DwLe5xr9YJLYSAwME4glkdCfl/lJ+fHi2XsEdZae24go9W+3HhXArjXKccP8t
ewKjfa/+r4SDUqLfhajcIKkNBHltCU90cA4Qi+wE/TSG3OuDl+CaBe+Zb7wBCyy4
arCVW5NsBLzcN5dnv7cAMDah/IT94ZXaIZCRcehx5/cJ1mb6vcAejaRKDwpXOd4f
1PDqjC1+0+39a7IBLXoOrdRIAQkCEPNehHxBgbpjzSMVwzr+y4Y4oyxGMdLmKFwa
O0t1Z6/Wb5jWV8dD1haVfk1oC4RfZDj76hSEbCyASB2++/JG+zArClgw";

        var packets = PacketList.Decode(Base64.Decode(data));
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhP384SecretSubkey)).Decrypt(Passphrase);
        var pkesk = (PublicKeyEncryptedSessionKey)packets[0];
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));
        Assert.That(pkesk.SessionKey, Is.Null);

        var decryptedpPkesk = pkesk.Decrypt(subkey);
        Assert.That(decryptedpPkesk.SessionKey, Is.Not.Null);
    }

    [Test]
    public void TestEncryptEcDhP384SessionKey()
    {
        var sessionKey = SessionKey.ProduceKey();
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhP384SecretSubkey)).Decrypt(Passphrase);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, subkey.PublicKey);
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));

        var packets =  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(subkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
        Assert.That(sessionKey.Symmetric, Is.EqualTo(decryptedPkesk.SessionKey!.Symmetric));
    }

    [Test]
    public void TestDecryptEcDhBrainpoolSessionKey()
    {
        var data = @"hH4DCKVb2x1nPV0SAgMEXc56LqYoYJmNo0hSbjHJqqnsjjJCcQJUr7RCyIew8y1B
uonkedTN08+6B6z1DcuHXr1CtWmo8O1RfA1bIAWpijCapYOMczR8UvO2BUixisIx
lyfm0MBhx1pLnNVKCuvgAu2t9DDoTo2E8HpeHfLNC1DUSAEJAhCosmYmOp+c0Jy/
a/vBHQm/YVjRG3ixReDpp5R5PpBQJJei/xwMS733bwLriGSWBkdLcEKk49Ec9btE
NeGzlkMV4z0dRA==";

        var packets = PacketList.Decode(Base64.Decode(data));
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhBrainpoolSecretSubkey)).Decrypt(Passphrase);
        var pkesk = (PublicKeyEncryptedSessionKey)packets[0];
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));
        Assert.That(pkesk.SessionKey, Is.Null);

        var decryptedpPkesk = pkesk.Decrypt(subkey);
        Assert.That(decryptedpPkesk.SessionKey, Is.Not.Null);
    }

    [Test]
    public void TestEncryptEcDhBrainpoolSessionKey()
    {
        var sessionKey = SessionKey.ProduceKey();
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhBrainpoolSecretSubkey)).Decrypt(Passphrase);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, subkey.PublicKey);
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));

        var packets =  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(subkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
        Assert.That(sessionKey.Symmetric, Is.EqualTo(decryptedPkesk.SessionKey!.Symmetric));
    }

    [Test]
    public void TestDecryptEcDhCurve25519SessionKey()
    {
        var data = @"hF4DBE6sk/C2nqASAQdAXZXMsrK2k5aAeJ0gl+RI4xIW6yCzM95FWxk4p/NGRiIw
KPENvQMA3yieBRk2otUFUf2ryA3IcgeiAzwiFB16tlgTy1HMJ8k+/fr9esnXHkRr
1EgBCQIQE1IPf72JCyfRVzSTyCZ8pHutG2zjRmzxCReF23S+7IlQ1asCq2Zjn9I2
AYd6zKgVJVb+5kvc/i034xNKjDl9IXOd7AE=";

        var packets = PacketList.Decode(Base64.Decode(data));
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhCurve25519SecretSubkey)).Decrypt(Passphrase);
        var pkesk = (PublicKeyEncryptedSessionKey)packets[0];
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));
        Assert.That(pkesk.SessionKey, Is.Null);

        var decryptedpPkesk = pkesk.Decrypt(subkey);
        Assert.That(decryptedpPkesk.SessionKey, Is.Not.Null);
    }

    [Test]
    public void TestEncryptEcDhCurve25519SessionKey()
    {
        var sessionKey = SessionKey.ProduceKey();
        var subkey = SecretSubkey.FromBytes(Base64.Decode(EcdhCurve25519SecretSubkey)).Decrypt(Passphrase);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, subkey.PublicKey);
        Assert.That(subkey.KeyId, Is.EqualTo(pkesk.KeyId));

        var packets =  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(subkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
        Assert.That(sessionKey.Symmetric, Is.EqualTo(decryptedPkesk.SessionKey!.Symmetric));
    }

    [Test]
    public void TestX25519AeadOcbDecryption()
    {
        var subkeyData = "BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24EL4=";
        var pkeskData = "BiEGEsg/HnBvYwj+FRpBd0Oh8DN5DpPpl4SI0ds3jamTCIUZh88Y1fG1P4F8zloATPOTzIlYvdwGXyX4SvUJsX3TZ2QY3qNVQ3lWYXkB4GlX+8qKakeltRU+jTq3";
        var seipdData = "AgcCBmFkFlNb4LBxbWDgUqVsTEB/nrNrDvr+mtCg35sDPGmiG6nr0sDslb9WnSXJme5KPeFwWPQN+otMaCvj+7vXsn6w9Zu1AF+Ax8b0A4jDCtQGqwUT3Nb5/XN2VihuEXfQD4iK2zHE";

        var subkey = SecretSubkey.FromBytes(Base64.Decode(subkeyData));
        var pkesk = PublicKeyEncryptedSessionKey.FromBytes(Base64.Decode(pkeskData)).Decrypt(subkey);
        var sessionKey = pkesk.SessionKey;
        Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("dd708f6fa1ed65114d68d2343e7c2f1d")));

        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData)).DecryptWithSessionKey(sessionKey);
        var literalData = (LiteralData)seipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestX25519Encryption()
    {
        var sessionKey = SessionKey.ProduceKey(SymmetricAlgorithm.Aes128);
        var secretSubkey = SecretSubkey.Generate(KeyAlgorithm.X25519);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, secretSubkey);
        Assert.That(secretSubkey.Fingerprint, Is.EqualTo(pkesk.KeyFingerprint));

        var packets=  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(secretSubkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
    }

    [Test]
    public void TestX448Encryption()
    {
        var sessionKey = SessionKey.ProduceKey();
        var secretSubkey = SecretSubkey.Generate(KeyAlgorithm.X448);
        var pkesk = PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, secretSubkey);
        Assert.That(secretSubkey.Fingerprint, Is.EqualTo(pkesk.KeyFingerprint));

        var packets=  PacketList.Decode(pkesk.Encode());
        var decryptedPkesk = ((PublicKeyEncryptedSessionKey)packets[0]).Decrypt(secretSubkey);
        Assert.That(sessionKey.EncryptionKey, Is.EqualTo(decryptedPkesk.SessionKey!.EncryptionKey));
    }
}
