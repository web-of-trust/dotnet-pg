using DotNetPG.Common;
using DotNetPG.Enum;
using DotNetPG.Packet;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Packet;

public class CompressionTest
{
    private const string Passphrase = "password";
    private const string LiteralText = "Hello PHP PG\n";

    [Test]
    public void TestZip()
    {
        var text = Helper.GeneratePassword(10000);
        var literalData = LiteralData.FromText(text);
        var packets = new PacketList([literalData]);
        var compressed = CompressedData.FromPacketList(packets, CompressionAlgorithm.Zip);
        Assert.That(compressed.PacketList, Is.SameAs(packets));

        var decompressed = CompressedData.FromBytes(compressed.ToBytes());
        var packet = (LiteralData)decompressed.PacketList[0];
        Assert.Multiple(() =>
        {
            Assert.That(decompressed.Algorithm, Is.EqualTo(CompressionAlgorithm.Zip));
            Assert.That(packet.Text, Is.EqualTo(text));
        });
    }

    [Test]
    public void TestZlib()
    {
        var text = Helper.GeneratePassword(10000);
        var literalData = LiteralData.FromText(text);
        var packets = new PacketList([literalData]);
        var compressed = CompressedData.FromPacketList(packets, CompressionAlgorithm.Zlib);
        Assert.That(compressed.PacketList, Is.SameAs(packets));

        var decompressed = CompressedData.FromBytes(compressed.ToBytes());
        var packet = (LiteralData)decompressed.PacketList[0];
        Assert.Multiple(() =>
        {
            Assert.That(decompressed.Algorithm, Is.EqualTo(CompressionAlgorithm.Zlib));
            Assert.That(packet.Text, Is.EqualTo(text));
        });
    }

    [Test]
    public void TestBZip2()
    {
        var text = Helper.GeneratePassword(10000);
        var literalData = LiteralData.FromText(text);
        var packets = new PacketList([literalData]);
        var compressed = CompressedData.FromPacketList(packets, CompressionAlgorithm.BZip2);
        Assert.That(compressed.PacketList, Is.SameAs(packets));

        var decompressed = CompressedData.FromBytes(compressed.ToBytes());
        var packet = (LiteralData)decompressed.PacketList[0];
        Assert.Multiple(() =>
        {
            Assert.That(decompressed.Algorithm, Is.EqualTo(CompressionAlgorithm.BZip2));
            Assert.That(packet.Text, Is.EqualTo(text));
        });
    }

    [Test]
    public void TestZipDecompress()
    {
        const string data = @"jA0ECQMCRq12Ney7cav/0kIBVtvCp7e/6bftnl80wIN/ocPyTIoNgZUzAucL8Yxa
bZ7L0eBy4u8hgAVtrJCtETOLYeFMS51S/7ErdqyksWx9osw=";

        var packets = PacketList.Decode(Base64.Decode(data));
        var skesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        var seip = ((SymEncryptedIntegrityProtectedData)packets[1]).Decrypt(sessionKey!.EncryptionKey, sessionKey.Symmetric);
        var compressed = (CompressedData)seip.PacketList![0];
        var literalData = (LiteralData)compressed.PacketList[0];

        Assert.Multiple(() =>
        {
            Assert.That(compressed.Algorithm, Is.EqualTo(CompressionAlgorithm.Zip));
            Assert.That(literalData.Text, Is.EqualTo(LiteralText));
        });
    }

    [Test]
    public void TestZlibDecompress()
    {
        const string data = @"jA0ECQMCLRbDkykeeZn/0kgBj3MScClX8/qZbP/HHT1XMXe8oc0FRSN8u6p+JbeC
cBZXWFgKE6GfHoK+8dlqnQYyPb9Xgh4MtFkw3OSFG9oO10Ggjuupq5Q=";

        var packets = PacketList.Decode(Base64.Decode(data));
        var skesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        var seip = ((SymEncryptedIntegrityProtectedData)packets[1]).Decrypt(sessionKey!.EncryptionKey, sessionKey.Symmetric);
        var compressed = (CompressedData)seip.PacketList![0];
        var literalData = (LiteralData)compressed.PacketList[0];

        Assert.Multiple(() =>
        {
            Assert.That(compressed.Algorithm, Is.EqualTo(CompressionAlgorithm.Zlib));
            Assert.That(literalData.Text, Is.EqualTo(LiteralText));
        });
    }

    [Test]
    public void TestBZip2Decompress()
    {
        const string data = @"jA0ECQMCrf1YgAm7Evr/0m8BFPj2+nB5ipmTP0eWAAFxZCh4b7lTkE32a+nEABkg
kgYAl1ez6sJjNmyUYMzAWbfIEC0hoXioZKY6W/9KR7Ln0aK46/ZUGW3QKau7BwlY
64cgB5gvL4qH3TMmIaWMrJ+rr+zFD2RI+oakU2zAheg=";

        var packets = PacketList.Decode(Base64.Decode(data));
        var skesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        var seip = ((SymEncryptedIntegrityProtectedData)packets[1]).Decrypt(sessionKey!.EncryptionKey, sessionKey.Symmetric);
        var compressed = (CompressedData)seip.PacketList![0];
        var literalData = (LiteralData)compressed.PacketList[0];

        Assert.Multiple(() =>
        {
            Assert.That(compressed.Algorithm, Is.EqualTo(CompressionAlgorithm.BZip2));
            Assert.That(literalData.Text, Is.EqualTo(LiteralText));
        });
    }
}
