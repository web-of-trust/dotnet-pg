
namespace DotNetPG.Test.Common;

using System.Text.RegularExpressions;
using DotNetPG.Common;
using DotNetPG.Enum;

public class ArmorTest
{
    [Test]
    public void SignedMessageTest()
    {
        var random = new Random();
        byte[] data = new byte[1000];
        random.NextBytes(data);
        var text = Helper.ChunkSplit(Helper.GeneratePassword(1000), 100);
        const string hashAlgo = nameof(HashAlgorithm.Sha256);
        var armored = Armor.Encode(ArmorType.SignedMessage, data, [hashAlgo], text);
        Assert.Multiple(() =>
        {
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP SIGNED MESSAGE"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP SIGNATURE"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"END PGP SIGNATURE"), Is.EqualTo(true));
        });

        var armor = Armor.Decode(armored);
        Assert.Multiple(() =>
        {
            Assert.That(armor.Type, Is.EqualTo(ArmorType.SignedMessage));
            Assert.That(armor.Data, Is.EqualTo(data));
            Assert.That(armor.Text, Is.EqualTo(text));
        });
    }

    [Test]
    public void MessageTest()
    {
        var random = new Random();
        byte[] data = new byte[1000];
        random.NextBytes(data);
        var armored = Armor.Encode(ArmorType.Message, data, []);
        Assert.Multiple(() =>
        {
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP MESSAGE"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"END PGP MESSAGE"), Is.EqualTo(true));
        });

        var armor = Armor.Decode(armored);
        Assert.Multiple(() =>
        {
            Assert.That(armor.Type, Is.EqualTo(ArmorType.Message));
            Assert.That(armor.Data, Is.EqualTo(data));
        });
    }

    [Test]
    public void PublicKeyTest()
    {
        var random = new Random();
        byte[] data = new byte[1000];
        random.NextBytes(data);
        var armored = Armor.Encode(ArmorType.PublicKey, data, []);
        Assert.Multiple(() =>
        {
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP PUBLIC KEY BLOCK"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"END PGP PUBLIC KEY BLOCK"), Is.EqualTo(true));
        });

        var armor = Armor.Decode(armored);
        Assert.Multiple(() =>
        {
            Assert.That(armor.Type, Is.EqualTo(ArmorType.PublicKey));
            Assert.That(armor.Data, Is.EqualTo(data));
        });
    }

    [Test]
    public void PrivateKeyTest()
    {
        var random = new Random();
        byte[] data = new byte[1000];
        random.NextBytes(data);
        var armored = Armor.Encode(ArmorType.PrivateKey, data, []);
        Assert.Multiple(() =>
        {
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP PRIVATE KEY BLOCK"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"END PGP PRIVATE KEY BLOCK"), Is.EqualTo(true));
        });

        var armor = Armor.Decode(armored);
        Assert.Multiple(() =>
        {
            Assert.That(armor.Type, Is.EqualTo(ArmorType.PrivateKey));
            Assert.That(armor.Data, Is.EqualTo(data));
        });
    }

    [Test]
    public void SignatureTest()
    {
        var random = new Random();
        byte[] data = new byte[1000];
        random.NextBytes(data);
        var armored = Armor.Encode(ArmorType.Signature, data, []);
        Assert.Multiple(() =>
        {
            Assert.That(Regex.IsMatch(armored, @"BEGIN PGP SIGNATURE"), Is.EqualTo(true));
            Assert.That(Regex.IsMatch(armored, @"END PGP SIGNATURE"), Is.EqualTo(true));
        });

        var armor = Armor.Decode(armored);
        Assert.Multiple(() =>
        {
            Assert.That(armor.Type, Is.EqualTo(ArmorType.Signature));
            Assert.That(armor.Data, Is.EqualTo(data));
        });
    }
}
