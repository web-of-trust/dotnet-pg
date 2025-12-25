using DotNetPG.Common;
using DotNetPG.Enum;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Key;

[TestFixture]
public class PrivateKeyTest
{
    private const string Passphrase = "dotnetpg";

    private const string UserId = "Nguyen Van Nguyen <nguyennv1981@gmail.com>";

    private const string RsaPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=zDmd
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccNistP384PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEaUo/vxMFK4EEACIDAwShWpTI36as5whaeQhAb7nmDAloYAcpSnieMByS/JbS
DqbHQqK0y746KOxSOxBNjM4W6yEMhiyagZrmCWYKWk5uIz87A9JCph5zIsyEip67
tSnQBg2WnU8IKD1pI4SM537+BwMCdxinxpdBZE7/pMrPsEIt4tUK6TKJtmBrzW/W
C1MfU/ZbNf2crnY/Rm74xSEBIRUnKEbzin9XekuZwqbUWkDV4rPJyFad6BF/nACL
Mqiw0Qsji0gWvstmqyGjB2MU43q0Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5u
djE5ODFAZ21haWwuY29tPoizBBMTCQA7FiEEMB8L/jaO93Bhq25n96WvN2jymmoF
AmlKP78CGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ96WvN2jymmrd
MAF/fg+Qqi7SuMOj2PIORP3z6nvg68p4JTXocSyyusiMLoiJ1LibHbdtHkD3S3zf
yC19AYDIHIB6U1aZoAz7viG8C3HtnaX1wa04p9OzOgttC4NsVJFrVUKKlXghE74P
Hwql6ZOc1gRpSj+/EgUrgQQAIgMDBHUeK591AXXGJjYSurDyw4Gr2VcS2UD2MBAT
ewbVkZ14O01PW0c6dwmWD2fdRyiCCCN0I4+g9fn53yf/Sar7zQUjDP8wigpdXSqf
+zWBdiCEMsDoqe98xOaAmm5rJLVjggMBCQn+BwMC282BRFmx3rP/StX7OnGiMTl3
xCE33+VcmuMz5fL9Tp5pQroTQHgageYuPvfi6VCLl0UCHhhzEpQSSWAbcVmCIT7+
NFEMz8gr88fIRPad/P/lxnPRcf1De/pZ2J+i9lGImAQYEwkAIBYhBDAfC/42jvdw
YatuZ/elrzdo8ppqBQJpSj+/AhsMAAoJEPelrzdo8ppqVbMBfiUMM3VtXmfIM8uc
k3AbYKUS0EJqSsFxi/E88CZFRobKVAtuDTC/FkZAapWvjxyp1wGAsorLxX4syMHl
t7KN4XKuQksjXrXHIeShVuBrk8Ew4lwp29uB7sZwMzQk+jhlOyge
=6BLp
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccBrainpoolPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lKYEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlP4HAwIBqb0FlADk
2v8ncy7kx3ss5cZrYq/J/lLM5K7Lp23qGPlbO+OhBJ+7FIE7u8O53nJDgPEO9HWM
gFqyhJblt2sK2qgUfvCjDqo3mnixZ1L1tCpOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1
eWVubnYxOTgxQGdtYWlsLmNvbT6IkwQTEwgAOxYhBCP7/IKGPFi3f8F/0G6mMM70
xXvoBQJpSkASAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEG6mMM70
xXvoHywA/ij264z8bgVKfEQOZaQEf9AnSVYTQAg5zPRdOe8oug3rAQCkB4UcFMxi
Wu/PDK0pBfRzKG//sImcXD06epAgvD89A5yqBGlKQBISCSskAwMCCAEBBwIDBCyM
kXIHirMuOvLQDi655EU5EfA0PYgzw1VitebYzlJLE9eWg7M0Pod15NJuoQL7du44
/npX2xpPaEhbO32yRakDAQgH/gcDAqCPHopeVZng/3zqqFbTylVjZrP9KE9W/9Bf
SGsJViaqXye9zKTffbLZVz9F59RyPWS4nzf7t8XoYPaFNl41PEhidMG/uTu2gRQz
9kCMYYeIeAQYEwgAIBYhBCP7/IKGPFi3f8F/0G6mMM70xXvoBQJpSkASAhsMAAoJ
EG6mMM70xXvo0Y8BAIt3srVH8jDpoUs4fvjAlo4EAebKZ6wP8WHJ4lIilulEAP9f
M2eW+sS8HCEkqpccy8Imc0abq4+voVjMiis6bc4CCQ==
=79zs
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccCurve25519PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaUpAYRYJKwYBBAHaRw8BAQdAxNFrk1BAfIODwbzj7j+cQn+35C0ID1hj60Cy
U86oPb7+BwMCoUB0MyObPDn/gA4b4RCAteNQ/GahKnjJzKFfQmmb9NX97fSDj/dr
5BNzyRYracvpXi5P5czln4KrEfOIF8eWL0NHiUeYpdNBppYnpeD3IrQqTmd1eWVu
IFZhbiBOZ3V5ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+iJMEExYKADsWIQQ6
dYnwWZSnUDoorfViUvVkpTtJXgUCaUpAYQIbAwULCQgHAgIiAgYVCgkICwIEFgID
AQIeBwIXgAAKCRBiUvVkpTtJXuBLAQCPA/cVcjviwsa8fDCY8WW46xW8ZFeCn69i
N5gMYTiyRQD/W0zw1meGly9UndofQZY60vxm5klsPKCC6t+4iZqZ0wWJAbMEEAEK
AB0WIQTRCK9znXXCFbM9ac6tqwDmwVfMDQUCaUu2TgAKCRCtqwDmwVfMDZjNDACq
5vjMNMyYvBIA95PG88l1x2AV38f1B9uvAhmhIonWksrTXErCcO1ijQYJr1Q9hJQu
BeEZN15YJhzLoMuXwvCfyK6YIaTIQsbuYY/yA7yak1Ly/j/YYfa5ga+U0ENBQFPQ
hBC/DRtur3H1VYf54GuBMSGQffer6+9s7nclwnYPLIeefNnEf1S9yBX6er6++Xfq
27REaP4vLZfbs7+lo9YPGtDdH+H7zoy4ctmJx1raGw96tIOEcJYeEFwps0+n+ZAW
f5WkJeJcQlZ8urKvfjzc3aqpE3Q2wJmQ4ewYxc3wU2WZPDiurkDtoJqmvvVf2KRx
pumpe4K21x9AYeggduKrWHPIxYs4rxPUaqPT8iN6Jv15jW+Tps4xcF0kvxyfOWdR
CZ1bB/xMz2mC4f/PehpaNWAN/C2vw57sLVa7foi3YbUV2RRYwm5kG2ijkLmr8OmG
dXBttqkTrmFpVVqY9k1SfjVH45+1TXOVCDeEEA8lk0OH/LuqhB6A5EkvvrF2eYqc
iwRpSkBhEgorBgEEAZdVAQUBAQdAcwCnokWFZCcGwu+0MCh7vBjeHa5cgc1q413D
gKuPRE4DAQgH/gcDApGSCDvO+IFU/z8FJ/TEcaR19c8wkUmzJnN8U0vjjYfw9NDM
fvr4DhFVC9xy6qNasJUuWbozFQhnGflVeDzM3VC7BKwkDmXlcTZp1qScYPGIeAQY
FgoAIBYhBDp1ifBZlKdQOiit9WJS9WSlO0leBQJpSkBhAhsMAAoJEGJS9WSlO0le
03MA+gPUPzX0LqO+OuPmwiuYEJibUneKde3nU2NE5kGplgf2AP9rU8+rOkhvrj0t
Dt8BTpBpZ769B0GLXv0Pe6k4098TAg==
=bSaL
-----END PGP PRIVATE KEY BLOCK-----";

    [Test]
    public void TestReadRsaPrivateKey()
    {
        var privateKey = OpenPGP.ReadPrivateKey(RsaPrivateKey);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("d108af739d75c215b33d69ceadab00e6c157cc0d")));
            Assert.That(privateKey.KeyId, Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(privateKey.KeyLength, Is.EqualTo(3072));
            Assert.That(privateKey.Version, Is.EqualTo(4));
            Assert.That(privateKey.IsPrivate, Is.EqualTo(true));
            Assert.That(privateKey.IsEncrypted, Is.EqualTo(true));
            Assert.That(privateKey.IsDecrypted, Is.EqualTo(false));
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.EqualTo(true));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("d50cd8b840a4cd00b7f131df9c8d66a6aa2595c9")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("9c8d66a6aa2595c9")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(subkey.KeyLength, Is.EqualTo(3072));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.EqualTo(true));
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.EqualTo(true));
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("d108af739d75c215b33d69ceadab00e6c157cc0d")));
    }

    [Test]
    public void TestReadEccNistP384PrivateKey()
    {
        var privateKey = OpenPGP.ReadPrivateKey(EccNistP384PrivateKey);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("301f0bfe368ef77061ab6e67f7a5af3768f29a6a")));
            Assert.That(privateKey.KeyId, Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(384));
            Assert.That(privateKey.Version, Is.EqualTo(4));
            Assert.That(privateKey.IsPrivate, Is.EqualTo(true));
            Assert.That(privateKey.IsEncrypted, Is.EqualTo(true));
            Assert.That(privateKey.IsDecrypted, Is.EqualTo(false));
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.EqualTo(true));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("c06a2e728709664937a065de157b6b6097c7e917")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("157b6b6097c7e917")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(384));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.EqualTo(true));
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.EqualTo(true));
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("301f0bfe368ef77061ab6e67f7a5af3768f29a6a")));
    }

    [Test]
    public void TestReadEccBrainpoolPrivateKey()
    {
        var privateKey = OpenPGP.ReadPrivateKey(EccBrainpoolPrivateKey);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("23fbfc82863c58b77fc17fd06ea630cef4c57be8")));
            Assert.That(privateKey.KeyId, Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(256));
            Assert.That(privateKey.Version, Is.EqualTo(4));
            Assert.That(privateKey.IsPrivate, Is.EqualTo(true));
            Assert.That(privateKey.IsEncrypted, Is.EqualTo(true));
            Assert.That(privateKey.IsDecrypted, Is.EqualTo(false));
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.EqualTo(true));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("64bc0434baf20c6b1f5d3a7df02cc5df3d8e6fbf")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("f02cc5df3d8e6fbf")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(256));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.EqualTo(true));
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.EqualTo(true));
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("23fbfc82863c58b77fc17fd06ea630cef4c57be8")));
    }

    [Test]
    public void TestReadEccCurve25519PrivateKey()
    {
        var privateKey = OpenPGP.ReadPrivateKey(EccCurve25519PrivateKey);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("3a7589f05994a7503a28adf56252f564a53b495e")));
            Assert.That(privateKey.KeyId, Is.EqualTo(Hex.Decode("6252f564a53b495e")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.Version, Is.EqualTo(4));
            Assert.That(privateKey.IsPrivate, Is.EqualTo(true));
            Assert.That(privateKey.IsEncrypted, Is.EqualTo(true));
            Assert.That(privateKey.IsDecrypted, Is.EqualTo(false));
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.EqualTo(true));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("4b228834fe741a2181d0bb676dcdff1f03a14a84")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("6dcdff1f03a14a84")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.EqualTo(true));
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.EqualTo(true));
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("3a7589f05994a7503a28adf56252f564a53b495e")));
    }
}
