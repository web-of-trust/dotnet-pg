
namespace DotNetPG.Test.Common;

using Org.BouncyCastle.Utilities.Encoders;
using DotNetPG.Common;
using DotNetPG.Enum;
using DotNetPG.Packet;

public class S2KTest
{
    [Test]
    public void TestMode0Password1234()
    {
        const string data = "BAkAAg==";
        const string passphrase = "1234";
        byte[] salt = [];

        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Simple));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("7110eda4d09e062aa5e4a390b0a572ac0d2c0220f352b0d292b65164c2a67301"));
    }

    [Test]
    public void TestMode1Password123456()
    {
        const string data = "BAkBAqhCp6lZ+kIq";
        const string passphrase = "123456";
        byte[] salt = [0xa8, 0x42, 0xa7, 0xa9, 0x59, 0xfa, 0x42, 0x2a];

        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Salted));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("8b79077ca448f6fb3d3ad2a264d3b938d357c9fb3e41219fd962df960a9afa08"));
    }

    [Test]
    public void TestMode1PasswordFoobar()
    {
        const string data = "BAkBAryVWEWBPHw3";
        const string passphrase = "foobar";
        byte[] salt = [0xbc, 0x95, 0x58, 0x45, 0x81, 0x3c, 0x7c, 0x37];

        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Salted));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("b7d48aae9b943b22a4d390083e8460b5edfa118fe1688bf0c473b8094d1a8d10"));
    }

    [Test]
    public void TestMode3PasswordQwerty()
    {
        const string data = "BAkDAnhF8FtV97Se8Q==";
        const string passphrase = "qwerty";
        const int itCount = 241;
        byte[] salt = [0x78, 0x45, 0xf0, 0x5b, 0x55, 0xf7, 0xb4, 0x9e];

        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Iterated));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
            Assert.That(s2k.ItCount, Is.EqualTo(itCount));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash, s2k.ItCount);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("575ad156187a3f8cec11108309236eb499f1e682f0d1afadfac4ecf97613108a"));
    }

    [Test]
    public void TestMode3Password9876()
    {
        const string data = "BAkDArln6pZT22rIKw==";
        const string passphrase = "9876";
        const int itCount = 43;
        byte[] salt = [0xb9, 0x67, 0xea, 0x96, 0x53, 0xdb, 0x6a, 0xc8];

        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Iterated));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
            Assert.That(s2k.ItCount, Is.EqualTo(itCount));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash, s2k.ItCount);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("736c226b8c64e4e6d0325c6c552ef7c0738f98f48fed65fd8c93265103efa23a"));
    }

    [Test]
    public void TestMode3Aes192Password123()
    {
        const string data = "BAgDAo+BdMXZYcd57g==";
        const string passphrase = "123";
        const int itCount = 238;
        byte[] salt = [0x8f, 0x81, 0x74, 0xc5, 0xd9, 0x61, 0xc7, 0x79];
        
        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes192));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Iterated));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
            Assert.That(s2k.ItCount, Is.EqualTo(itCount));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash, s2k.ItCount);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("915e96fc694e7f90a6850b740125ea005199c725f3bd27e3"));
    }

    [Test]
    public void TestMode3TwofishPassword13Iterations0123456789()
    {
        const string data = "BAoDAlHt/BVFQGWs7g==";
        const string passphrase = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        const int itCount = 238;
        byte[] salt = [0x51, 0xed, 0xfc, 0x15, 0x45, 0x40, 0x65, 0xac];
        
        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Twofish));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Iterated));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
            Assert.That(s2k.ItCount, Is.EqualTo(itCount));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash, s2k.ItCount);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("ea264fada5a859c40d88a159b344ecf1f51ff327fdb3c558b0a7dc299777173e"));
    }

    [Test]
    public void TestMode3Aes128Password13Iterations0123456789()
    {
        const string data = "BAcDAgbkYVykSPnd7g==";
        const string passphrase = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        const int itCount = 238;
        byte[] salt = [0x06, 0xe4, 0x61, 0x5c, 0xa4, 0x48, 0xf9, 0xdd];
        
        var skesk = SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(data));
        var s2k = (GenericS2K)skesk.S2k;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(s2k.Type, Is.EqualTo(S2kType.Iterated));
            Assert.That(s2k.Hash, Is.EqualTo(HashAlgorithm.Sha1));
            Assert.That(s2k.Salt, Is.EqualTo(salt));
            Assert.That(s2k.ItCount, Is.EqualTo(itCount));
        });

        s2k = new GenericS2K(salt, s2k.Type, s2k.Hash, s2k.ItCount);
        var keySize = (Helper.SymmetricKeySize(skesk.Symmetric) + 7) >> 3;
        var key = s2k.ProduceKey(passphrase, keySize);
        Assert.That(Hex.Encode(key), Is.EqualTo("f3d0ce52ed6143637443e3399437fd0f"));
    }

    [Test]
    public void Test4Iterations1MB16KeyLengthArgon2S2K()
    {
        const string password = "password";
        var salt = "dH3Z8hGL7bBUyp1i"u8.ToArray();
        var hash = "eaf0095c8412e432cb9ff172957fef91";
        var s2k = new Argon2S2K(salt, 4, 1, 10);
        Assert.That(Hex.Encode(s2k.ProduceKey(password, 16)), Is.EqualTo(hash));
    }

    [Test]
    public void Test4Iterations64MB16KeyLengthArgon2S2K()
    {
        const string password = "password";
        var salt = "IeCBTBvkzbmxT87I"u8.ToArray();
        var hash = "050ebb7bcb8c1165502af049a664f2db";
        var s2k = new Argon2S2K(salt, 4, 1, 16);
        Assert.That(Hex.Encode(s2k.ProduceKey(password, 16)), Is.EqualTo(hash));
    }

    [Test]
    public void Test4Iterations10MB32KeyLengthArgon2S2K()
    {
        const string password = "password";
        var salt = "KtPeAgudgN7xrgUK"u8.ToArray();
        var hash = "66b3d1c15f544eae5810c29381ad477167d5a1d5360c9b97340bd5b8b06c589b";
        var s2k = new Argon2S2K(salt, 4, 1, 10);
        Assert.That(Hex.Encode(s2k.ProduceKey(password, 32)), Is.EqualTo(hash));
    }

    [Test]
    public void Test4Iterations64MB32KeyLengthArgon2S2K()
    {
        const string password = "password";
        var salt = "D85Euo8RwvlkUxb5"u8.ToArray();
        var hash = "cb1f8f04ec5ecb681e4ffb2665af6e4ad6aed540b5e62f625f48c834e8b88fa6";
        var s2k = new Argon2S2K(salt, 4, 1, 16);
        Assert.That(Hex.Encode(s2k.ProduceKey(password, 32)), Is.EqualTo(hash));
    }
}
