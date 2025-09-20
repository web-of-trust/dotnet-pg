
using System.Text;
using DotNetPG.Enum;
using DotNetPG.Packet;
using DotNetPG.Packet.Key;
using DotNetPG.Type;
using Org.BouncyCastle.Utilities.Encoders;

namespace Test.Packet;

public class AeadTest
{
    private const string LiteralText = "Hello, world!\n";

    [Test]
    public void TestAeadEaxDecrypt()
    {
        var key = Hex.Decode("86f1efb86952329f24acd3bfd0e5346d");
        var iv = Hex.Decode("b732379f73c4928de25facfe6517ec10");
        var bytes = Hex.Decode("0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476");

        var aepd = AeadEncryptedData.FromBytes(bytes);
        Assert.Multiple(() =>
        {
            Assert.That(aepd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(aepd.Aead, Is.EqualTo(AeadAlgorithm.Eax));
            Assert.That(aepd.ChunkSize, Is.EqualTo(14));
            Assert.That(aepd.Iv, Is.EqualTo(iv));
        });

        var decrypt = aepd.Decrypt(key);
        var literalData = (ILiteralData)decrypt.PacketList![0];
        Assert.That(literalData.Data, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadOcbDecrypt()
    {
        var key = Hex.Decode("d1f01ba30e130aa7d2582c16e050ae44");
        var iv = Hex.Decode("5ed2bc1e470abe8f1d644c7a6c8a56");
        var bytes = Hex.Decode("0107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098");

        var aepd = AeadEncryptedData.FromBytes(bytes);
        Assert.Multiple(() =>
        {
            Assert.That(aepd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(aepd.Aead, Is.EqualTo(AeadAlgorithm.Ocb));
            Assert.That(aepd.ChunkSize, Is.EqualTo(14));
            Assert.That(aepd.Iv, Is.EqualTo(iv));
        });

        var decrypt = aepd.Decrypt(key);
        var literalData = (ILiteralData)decrypt.PacketList![0];
        Assert.That(literalData.Data, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadEncrypt()
    {
        var sessionKey = SessionKey.ProduceKey();
        var aepd = AeadEncryptedData.EncryptPacketsWithSessionKey(
            sessionKey, new PacketList([LiteralData.FromText(LiteralText)]), AeadAlgorithm.Ocb
        );
        Assert.Multiple(() =>
        {
            Assert.That(aepd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(aepd.Aead, Is.EqualTo(AeadAlgorithm.Ocb));
        });

        var encrypted = AeadEncryptedData.FromBytes(aepd.ToBytes());
        var decrypt = encrypted.Decrypt(sessionKey.EncryptionKey);
        var literalData = (ILiteralData)decrypt.PacketList![0];
        Assert.That(Encoding.UTF8.GetString(literalData.Data), Is.EqualTo(LiteralText.TrimEnd()));
    }
}
