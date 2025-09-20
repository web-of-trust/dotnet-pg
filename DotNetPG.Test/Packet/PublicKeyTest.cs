using DotNetPG.Enum;
using DotNetPG.Packet;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Packet;

public class PublicKeyTest
{
    [Test]
    public void TestRsaPublicKey()
    {
        const string keyData = @"BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("fc5004df9473277107eaa605184d0dc4f5c532b2")));
            Assert.That(publicKey.KeyId, Is.EqualTo(Hex.Decode("184d0dc4f5c532b2")));
            Assert.That(publicKey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestRsaPublicSubkey()
    {
        const string keyData = @"BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
MHBMlyq+QLfPuvPg187E0nsi1fh+P6sJ+gjNjSibyDdsBjHW6ZDksoB7lO5NhSCnzo63kMlP7QBH
hvOWaZSUHG3JqCsdElDSHkMrHpVzpyco+bTs7XK/E1iS0kC32yE7ShV/rltvl8hUKZF1npG3ytka
fegaEYESkM32/vygrCOWNC1Tea7kWe1A0+/ZYbgPh3blorNGICkUqiKfST9Xq26Lb67Kc38Gxjij
X9LAnOoxEyCjmCv/+ajNIDvMSQOtnTCapLpRrhLlzjvIDtOnABEBAAE=";

        var subkey = PublicSubkey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("42badbbe0f2acabacd6cac7c4be1b3a621ef906f")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("4be1b3a621ef906f")));
            Assert.That(subkey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEcdsaP384PublicKey()
    {
        const string keyData = @"BGRYd7UTBSuBBAAiAwME3Z/lmJrDGnYHvT7xe5ei8xFfsCsrH+6AjmSftcJEYCCTy4CupXlvp5wb
FLQ2klduC2c09LzjULVFn4uQKdMacYb7X0UjI2q6MLGP1fpmg7mq4F8myVJx6lkvpHK44xDh";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("05c085492d14f90976e7c2b6b202d9e2eada440c")));
            Assert.That(publicKey.KeyId, Is.EqualTo(Hex.Decode("b202d9e2eada440c")));
            Assert.That(publicKey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEcdhP384PublicSubkey()
    {
        const string keyData = @"BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME1VbDPhf0DN0N
c1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2x3zGqsxe1lvrYDVj9gDYAwEJ
CQ==";

        var subkey = PublicSubkey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("c0b7b9c6bf5824b6")));
            Assert.That(subkey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEcdsaBrainpoolP256PublicKey()
    {
        const string keyData = @"BGRYXMETCSskAwMCCAEBBwIDBHKh5xdXoTfino6vulZBw4fl5lMtKgzXIeG9zhJuBInpE7gOlxes
07/JY2b9aIUph0fAku1xE+ljP5I/5pI5qrQ=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("06fee3085d46dc007c0ec2f01cbcd043db44c5d6")));
            Assert.That(publicKey.KeyId, Is.EqualTo(Hex.Decode("1cbcd043db44c5d6")));
            Assert.That(publicKey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEcdhBrainpoolP256PublicSubkey()
    {
        const string keyData = @"BGRYXMESCSskAwMCCAEBBwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47Sr
B3ZgWmrx1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH";

        var subkey = PublicSubkey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("457b5979545fba09be179db808a55bdb1d673d5d")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("08a55bdb1d673d5d")));
            Assert.That(subkey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEddsaCurve25519PublicKey()
    {
        const string keyData = "BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("1c4116eb2b58cfa196c57ddbbdff135160c56a0b")));
            Assert.That(publicKey.KeyId, Is.EqualTo(Hex.Decode("bdff135160c56a0b")));
            Assert.That(publicKey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestEcdhCurve25519PublicSubkey()
    {
        const string keyData = "BGRYXQUSCisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMBCAc=";

        var subkey = PublicSubkey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("8efa53a375fc569aa9ca564a044eac93f0b69ea0")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("044eac93f0b69ea0")));
            Assert.That(subkey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestVersion4Ed25519LegacyPublicKey()
    {
        const string keyData = "BFPzXwsWCSsGAQQB2kcPAQEHQD8JiZS92RbtQFMZeTTkqHyAczoSgNYvgBCZLkPuOyQG";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("c959bdbafa32a2f89a153b678cfde12197965a9a")));
            Assert.That(publicKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EdDsaLegacy));
            Assert.That(publicKey.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void TestVersion6PublicKey()
    {
        const string keyData = "BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj";

        var publicKey = PublicKey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(publicKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(publicKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(publicKey.Version, Is.EqualTo(6));
        });
    }

    [Test]
    public void TestVersion6PublicSubkey()
    {
        const string keyData = "BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1";

        var subkey = PublicSubkey.FromBytes(Base64.Decode(keyData));
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.Version, Is.EqualTo(6));
        });
    }
}
