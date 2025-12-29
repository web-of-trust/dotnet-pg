namespace DotNetPG.Test.Key;

using DotNetPG.Common;
using Enum;

[TestFixture]
public class GenerateKeyTest
{
    private const string Passphrase = "dotnetpg";

    private const string UserId = "Nguyen Van Nguyen <nguyennv1981@gmail.com>";

    [Test]
    public void TestGenerateRsaKey()
    {
        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(privateKey.KeyLength, Is.EqualTo(2048));
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.True);
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(subkey.KeyLength, Is.EqualTo(2048));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
            Assert.That(user.IsPrimary, Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEccNistKey()
    {
        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Ecc, curve: EcCurve.Secp384R1);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(384));
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.True);
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(384));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
            Assert.That(user.IsPrimary, Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEccBrainpoolKey()
    {
        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Ecc, curve: EcCurve.BrainpoolP256R1);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(256));
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.True);
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(256));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
            Assert.That(user.IsPrimary, Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));
    }

    [Test]
    public void TestGenerateEccEd25519Key()
    {
        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Ecc, curve: EcCurve.Ed25519);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EdDsaLegacy));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.IsEncrypted, Is.True);
            Assert.That(privateKey.IsDecrypted, Is.True);
        });

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
            Assert.That(user.IsPrimary, Is.True);
        });

        var publicKey = privateKey.PublicKey;
        Assert.That(publicKey.Fingerprint, Is.EqualTo(privateKey.Fingerprint));
    }

    [Test]
    public void TestGenerateV6RsaKeyWithAeadProtect()
    {
        Config.PresetRfc = PresetRfc.Rfc9580;
        Config.AeadProtect = true;

        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(privateKey.KeyLength, Is.EqualTo(2048));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.AeadProtected, Is.True);
        });

        var signature = privateKey.DirectSignatures[0];
        Assert.That(signature.Version, Is.EqualTo(6));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.RsaGeneral));
            Assert.That(subkey.KeyLength, Is.EqualTo(2048));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.SelfSignatures[0].Version, Is.EqualTo(6));
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        Config.PresetRfc = PresetRfc.Rfc4880;
        Config.AeadProtect = false;
    }

    [Test]
    public void TestGenerateV6EccKeyWithAeadProtect()
    {
        Config.PresetRfc = PresetRfc.Rfc9580;
        Config.AeadProtect = true;

        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Ecc);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDsa));
            Assert.That(privateKey.KeyLength, Is.EqualTo(521));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.AeadProtected, Is.True);
        });

        var signature = privateKey.DirectSignatures[0];
        Assert.That(signature.Version, Is.EqualTo(6));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.EcDh));
            Assert.That(subkey.KeyLength, Is.EqualTo(521));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.SelfSignatures[0].Version, Is.EqualTo(6));
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        Config.PresetRfc = PresetRfc.Rfc4880;
        Config.AeadProtect = false;
    }

    [Test]
    public void TestGenerateV6Curve25519KeyWithAeadProtect()
    {
        Config.AeadProtect = true;

        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Curve25519);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed25519));
            Assert.That(privateKey.KeyLength, Is.EqualTo(255));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.AeadProtected, Is.True);
        });

        var signature = privateKey.DirectSignatures[0];
        Assert.That(signature.Version, Is.EqualTo(6));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X25519));
            Assert.That(subkey.KeyLength, Is.EqualTo(255));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.SelfSignatures[0].Version, Is.EqualTo(6));
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        Config.AeadProtect = false;
    }

    [Test]
    public void TestGenerateV6Curve448KeyWithAeadProtect()
    {
        Config.AeadProtect = true;

        var privateKey = OpenPGP.GenerateKey([UserId], Passphrase, KeyType.Curve448);
        Assert.Multiple(() =>
        {
            Assert.That(privateKey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.Ed448));
            Assert.That(privateKey.KeyLength, Is.EqualTo(448));
            Assert.That(privateKey.Version, Is.EqualTo(6));
            Assert.That(privateKey.AeadProtected, Is.True);
        });

        var signature = privateKey.DirectSignatures[0];
        Assert.That(signature.Version, Is.EqualTo(6));

        var subkey = privateKey.Subkeys[0];
        Assert.Multiple(() =>
        {
            Assert.That(subkey.KeyAlgorithm, Is.EqualTo(KeyAlgorithm.X448));
            Assert.That(subkey.KeyLength, Is.EqualTo(448));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.Verify(), Is.True);
        });

        var user = privateKey.Users[0];
        Assert.Multiple(() =>
        {
            Assert.That(user.SelfSignatures[0].Version, Is.EqualTo(6));
            Assert.That(user.UserId, Is.EqualTo(UserId));
            Assert.That(user.Verify(), Is.True);
        });

        Config.AeadProtect = false;
    }
}
