namespace DotNetPG.Test.Key;

using DotNetPG.Common;
using Enum;
using Org.BouncyCastle.Utilities.Encoders;

[TestFixture]
public class PrivateKeyTest
{
    private const string Passphrase = "password";

    private const string UserId = "Nguyen Van Nguyen <nguyennv1981@gmail.com>";

    private const string Email = "nguyennv1981@gmail.com";

    private const string RsaPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=BhVr
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccNistP384PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEaUo/vxMFK4EEACIDAwShWpTI36as5whaeQhAb7nmDAloYAcpSnieMByS/JbS
DqbHQqK0y746KOxSOxBNjM4W6yEMhiyagZrmCWYKWk5uIz87A9JCph5zIsyEip67
tSnQBg2WnU8IKD1pI4SM537+BwMCaGiqteO7t63/kuJPTI90t4+r9nnTu2ihnZoX
rD4ZyZqndtia1SwpK8nfWelj/PCB4xn7VAZbCEI8FObNio2WNBnblcJL2B2Oju3e
xKB3oYAkmngmq2yYBvwXBz3dmWG0Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5u
djE5ODFAZ21haWwuY29tPoizBBMTCQA7FiEEMB8L/jaO93Bhq25n96WvN2jymmoF
AmlKP78CGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ96WvN2jymmrd
MAF/fg+Qqi7SuMOj2PIORP3z6nvg68p4JTXocSyyusiMLoiJ1LibHbdtHkD3S3zf
yC19AYDIHIB6U1aZoAz7viG8C3HtnaX1wa04p9OzOgttC4NsVJFrVUKKlXghE74P
Hwql6ZOc1gRpSj+/EgUrgQQAIgMDBHUeK591AXXGJjYSurDyw4Gr2VcS2UD2MBAT
ewbVkZ14O01PW0c6dwmWD2fdRyiCCCN0I4+g9fn53yf/Sar7zQUjDP8wigpdXSqf
+zWBdiCEMsDoqe98xOaAmm5rJLVjggMBCQn+BwMCTU/sQl1syWP/aMnTHl0xAvDK
fj8cQwleIk4jqzNAzssBt4t/ZRoU+uSXmJ8QaZOUb2ZVt0FIilWR8HIt+9EmOAmK
Rx2mmw3WzyQ/Pxb5Z6uIO1hz7UEk0pGeE6qylHuImAQYEwkAIBYhBDAfC/42jvdw
YatuZ/elrzdo8ppqBQJpSj+/AhsMAAoJEPelrzdo8ppqVbMBfiUMM3VtXmfIM8uc
k3AbYKUS0EJqSsFxi/E88CZFRobKVAtuDTC/FkZAapWvjxyp1wGAsorLxX4syMHl
t7KN4XKuQksjXrXHIeShVuBrk8Ew4lwp29uB7sZwMzQk+jhlOyge
=WqW7
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccBrainpoolPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lKYEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlP4HAwJkuknkdbJ0
0/+zyIJY2R2jle684DEY8AY6WzJZlD76YTqoG5wphk+vvExY5cbALPWnJOO1FZUH
l/QiH+1cSCB/lV72NvwANRdYzDPA1yT9tCpOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1
eWVubnYxOTgxQGdtYWlsLmNvbT6IkwQTEwgAOxYhBCP7/IKGPFi3f8F/0G6mMM70
xXvoBQJpSkASAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEG6mMM70
xXvoHywA/ij264z8bgVKfEQOZaQEf9AnSVYTQAg5zPRdOe8oug3rAQCkB4UcFMxi
Wu/PDK0pBfRzKG//sImcXD06epAgvD89A5yqBGlKQBISCSskAwMCCAEBBwIDBCyM
kXIHirMuOvLQDi655EU5EfA0PYgzw1VitebYzlJLE9eWg7M0Pod15NJuoQL7du44
/npX2xpPaEhbO32yRakDAQgH/gcDAnTDuDLpNF1U/0ad/xSOcP2ZLiwOIszsyCHe
x39qu8f3EN8ZWiC6ozLkS5I0O8gPZrJYlZqLqa3ZEls6l2/auHPVg9Uvzj0ZmEwa
dssUuE6IeAQYEwgAIBYhBCP7/IKGPFi3f8F/0G6mMM70xXvoBQJpSkASAhsMAAoJ
EG6mMM70xXvo0Y8BAIt3srVH8jDpoUs4fvjAlo4EAebKZ6wP8WHJ4lIilulEAP9f
M2eW+sS8HCEkqpccy8Imc0abq4+voVjMiis6bc4CCQ==
=FrF9
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccCurve25519PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaUpAYRYJKwYBBAHaRw8BAQdAxNFrk1BAfIODwbzj7j+cQn+35C0ID1hj60Cy
U86oPb7+BwMC1CeSZdUORST/aVd530V+DW5zuycHwH/RwoJ7Fs1lsbK0irLBs3sH
sfXQkd/c9hW76EfkZiR2JIiJK46u1jX/SFI0ae8l/5130it2HO2rF7QqTmd1eWVu
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
gKuPRE4DAQgH/gcDAl+Lah979ZBs/1p4eEQliiPQ21yeehBx2czJYfSLxVA96GW1
QHlbn0viwO6B0TVd5TkqqPFu91hZ21STZxzmIm70IqaOegvXzQr8HplfwpGIeAQY
FgoAIBYhBDp1ifBZlKdQOiit9WJS9WSlO0leBQJpSkBhAhsMAAoJEGJS9WSlO0le
03MA+gPUPzX0LqO+OuPmwiuYEJibUneKde3nU2NE5kGplgf2AP9rU8+rOkhvrj0t
Dt8BTpBpZ769B0GLXv0Pe6k4098TAg==
=AxjL
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
            Assert.That(privateKey.IsPrivate, Is.True);
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.False);
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.True);

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("d50cd8b840a4cd00b7f131df9c8d66a6aa2595c9")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("9c8d66a6aa2595c9")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(subkey.KeyLength, Is.EqualTo(3072));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("d108af739d75c215b33d69ceadab00e6c157cc0d")));

        privateKey = privateKey.AddUsers([Email]).AddSubkey(passphrase, KeyAlgorithm.RsaSign);
        user = privateKey.Users[1];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(Email));
            Assert.That(user.Verify(), Is.True);
        });
        subkey = privateKey.Subkeys[1];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaSign));
            Assert.That(subkey.KeyLength, Is.EqualTo(2048));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });
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
            Assert.That(privateKey.IsPrivate, Is.True);
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.False);
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.True);

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("c06a2e728709664937a065de157b6b6097c7e917")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("157b6b6097c7e917")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(384));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("301f0bfe368ef77061ab6e67f7a5af3768f29a6a")));

        privateKey = privateKey.AddUsers([Email]).AddSubkey(passphrase, KeyAlgorithm.EcDsa, ecCurve: EcCurve.Secp384R1);
        user = privateKey.Users[1];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(Email));
            Assert.That(user.Verify(), Is.True);
        });
        subkey = privateKey.Subkeys[1];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(subkey.KeyLength, Is.EqualTo(384));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });
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
            Assert.That(privateKey.IsPrivate, Is.True);
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.False);
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.True);

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("64bc0434baf20c6b1f5d3a7df02cc5df3d8e6fbf")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("f02cc5df3d8e6fbf")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(256));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("23fbfc82863c58b77fc17fd06ea630cef4c57be8")));

        privateKey = privateKey.AddUsers([Email]).AddSubkey(passphrase, KeyAlgorithm.EcDsa, ecCurve: EcCurve.BrainpoolP256R1);
        user = privateKey.Users[1];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(Email));
            Assert.That(user.Verify(), Is.True);
        });
        subkey = privateKey.Subkeys[1];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(subkey.KeyLength, Is.EqualTo(256));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });
    }

    [Test]
    public void TestReadEccCurve25519PrivateKey()
    {
        var privateKey = OpenPGP.ReadPrivateKey(EccCurve25519PrivateKey);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("3a7589f05994a7503a28adf56252f564a53b495e")));
            Assert.That(privateKey.KeyId, Is.EqualTo(Hex.Decode("6252f564a53b495e")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EdDsaLegacy));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.Version, Is.EqualTo(4));
            Assert.That(privateKey.IsPrivate, Is.True);
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.False);
        });

        privateKey = privateKey.Decrypt(Passphrase);
        Assert.That(privateKey.IsDecrypted, Is.True);

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("4b228834fe741a2181d0bb676dcdff1f03a14a84")));
            Assert.That(subkey.KeyId, Is.EqualTo(Hex.Decode("6dcdff1f03a14a84")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("3a7589f05994a7503a28adf56252f564a53b495e")));

        privateKey = privateKey.AddUsers([Email]).AddSubkey(passphrase, KeyAlgorithm.EdDsaLegacy, ecCurve: EcCurve.Ed25519);
        user = privateKey.Users[1];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(Email));
            Assert.That(user.Verify(), Is.True);
        });
        subkey = privateKey.Subkeys[1];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EdDsaLegacy));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Version, Is.EqualTo(4));
            Assert.That(subkey.Verify(), Is.True);
        });
    }

    [Test]
    public void TestVersion6Curve25519SecretKey()
    {
        const string keyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----";

        var privateKey = OpenPGP.ReadPrivateKey(keyData);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.IsEncrypted, Is.False);
        });

        var directSig = privateKey.DirectSignatures[0];
        Assert.Multiple(() =>
        {
            Assert.That(directSig.IssuerFingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(directSig.Version, Is.EqualTo(6));
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.Version, Is.EqualTo(6));
        });

        var bindingSig = subkey.BindingSignatures[0];
        Assert.Multiple(() =>
        {
            Assert.That(bindingSig.IssuerFingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(bindingSig.Version, Is.EqualTo(6));
        });
        
        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
    }

    [Test]
    public void TestLockedVersion6Curve25519SecretKey()
    {
        const string keyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC
FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS
3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC
Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW
cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin
7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/
0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0
gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf
9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR
v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr
DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki
Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt
ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG
-----END PGP PRIVATE KEY BLOCK-----";

        var privateKey = OpenPGP.ReadPrivateKey(keyData);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.False);
            Assert.That(privateKey.AeadProtected, Is.True);
        });

        var directSig = privateKey.DirectSignatures[0];
        Assert.Multiple(() =>
        {
            Assert.That(directSig.IssuerFingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(directSig.Version, Is.EqualTo(6));
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.Fingerprint, Is.EqualTo(Hex.Decode("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885")));
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.Version, Is.EqualTo(6));
        });

        var bindingSig = subkey.BindingSignatures[0];
        Assert.Multiple(() =>
        {
            Assert.That(bindingSig.IssuerFingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
            Assert.That(bindingSig.Version, Is.EqualTo(6));
        });

        privateKey = privateKey.Decrypt("correct horse battery staple");
        Assert.That(privateKey.IsDecrypted, Is.True);

        var passphrase = Helper.GeneratePassword();
        var armoredPrivateKey = OpenPGP.EncryptPrivateKey(privateKey, passphrase).Armor();
        privateKey = OpenPGP.DecryptPrivateKey(armoredPrivateKey, passphrase);
        Assert.That(privateKey.Fingerprint, Is.EqualTo(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
        
        privateKey = privateKey.AddUsers([UserId]).AddSubkey(passphrase, KeyAlgorithm.Ed25519);
        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });
        subkey = privateKey.Subkeys[1];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.Verify(), Is.True);
        });
    }

    [Test]
    public void TestCertifyKey()
    {
        const string keyData = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlLQqTmd1eWVuIFZh
biBOZ3V5ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+iJMEExMIADsWIQQj+/yC
hjxYt3/Bf9BupjDO9MV76AUCaUpAEgIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIe
BwIXgAAKCRBupjDO9MV76B8sAP4o9uuM/G4FSnxEDmWkBH/QJ0lWE0AIOcz0XTnv
KLoN6wEApAeFHBTMYlrvzwytKQX0cyhv/7CJnFw9OnqQILw/PQO4VwRpSkASEgkr
JAMDAggBAQcCAwQsjJFyB4qzLjry0A4uueRFORHwND2IM8NVYrXm2M5SSxPXloOz
ND6HdeTSbqEC+3buOP56V9saT2hIWzt9skWpAwEIB4h4BBgTCAAgFiEEI/v8goY8
WLd/wX/QbqYwzvTFe+gFAmlKQBICGwwACgkQbqYwzvTFe+jRjwEAi3eytUfyMOmh
Szh++MCWjgQB5spnrA/xYcniUiKW6UQA/18zZ5b6xLwcISSqlxzLwiZzRpurj6+h
WMyKKzptzgIJ
=2/C1
-----END PGP PUBLIC KEY BLOCK-----";

        var publicKey = OpenPGP.ReadPublicKey(keyData);
        var privateKey = OpenPGP.DecryptPrivateKey(EccNistP384PrivateKey, Passphrase);
        var certifiedKey = OpenPGP.CertifyKey(privateKey, publicKey);
        Assert.Multiple(() =>
        {
            Assert.That(certifiedKey.Fingerprint, Is.EqualTo(publicKey.Fingerprint));
            Assert.That(publicKey.IsCertified(privateKey), Is.False);
            Assert.That(certifiedKey.IsCertified(privateKey), Is.True);
        });
    }

    [Test]
    public void TestRevokeKey()
    {
        const string keyData = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlLQqTmd1eWVuIFZh
biBOZ3V5ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+iJMEExMIADsWIQQj+/yC
hjxYt3/Bf9BupjDO9MV76AUCaUpAEgIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIe
BwIXgAAKCRBupjDO9MV76B8sAP4o9uuM/G4FSnxEDmWkBH/QJ0lWE0AIOcz0XTnv
KLoN6wEApAeFHBTMYlrvzwytKQX0cyhv/7CJnFw9OnqQILw/PQO4VwRpSkASEgkr
JAMDAggBAQcCAwQsjJFyB4qzLjry0A4uueRFORHwND2IM8NVYrXm2M5SSxPXloOz
ND6HdeTSbqEC+3buOP56V9saT2hIWzt9skWpAwEIB4h4BBgTCAAgFiEEI/v8goY8
WLd/wX/QbqYwzvTFe+gFAmlKQBICGwwACgkQbqYwzvTFe+jRjwEAi3eytUfyMOmh
Szh++MCWjgQB5spnrA/xYcniUiKW6UQA/18zZ5b6xLwcISSqlxzLwiZzRpurj6+h
WMyKKzptzgIJ
=2/C1
-----END PGP PUBLIC KEY BLOCK-----";

        var publicKey = OpenPGP.ReadPublicKey(keyData);
        var privateKey = OpenPGP.DecryptPrivateKey(EccNistP384PrivateKey, Passphrase);
        var revokedKey = OpenPGP.RevokeKey(privateKey, publicKey);
        Assert.Multiple(() =>
        {
            Assert.That(revokedKey.Fingerprint, Is.EqualTo(publicKey.Fingerprint));
            Assert.That(publicKey.IsRevoked(privateKey), Is.False);
            Assert.That(revokedKey.IsRevoked(privateKey), Is.True);
        });
    }
}
