using DotNetPG.Common;
using DotNetPG.Enum;
using DotNetPG.Packet;
using DotNetPG.Packet.Key;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Packet;

public class SKESKTest
{
    private const string Passphrase = "password";
    private const string LiteralText = "Hello, world!";

    [Test]
    public void TestEncryptNullSessionKey()
    {
        var skesk = SymmetricKeyEncryptedSessionKey.EncryptSessionKey(Passphrase);
        var seipd = SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(skesk.SessionKey!,
            new PacketList([LiteralData.FromText(LiteralText)]));
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Version, Is.EqualTo(4));
            Assert.That(skesk.Encrypted, Is.Empty);
            Assert.That(skesk.Symmetric, Is.EqualTo(skesk.SessionKey!.Symmetric));
            Assert.That(seipd.Encrypted, Is.Not.Empty);
        });

        var packets = PacketList.Decode((new PacketList([skesk, seipd])).Encode());
        var decryptedSkesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var decryptedSeipd = ((SymEncryptedIntegrityProtectedData)packets[1]).DecryptWithSessionKey(decryptedSkesk.SessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestEncryptSessionKey()
    {
        var sessionKey = SessionKey.ProduceKey(Config.PreferredSymmetric);
        var skesk = SymmetricKeyEncryptedSessionKey.EncryptSessionKey(Passphrase, sessionKey: sessionKey);
        var seipd = SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(sessionKey, new PacketList([LiteralData.FromText(LiteralText)]));
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Encrypted, Is.Not.Empty);
            Assert.That(seipd.Encrypted, Is.Not.Empty);
        });

        var packets = PacketList.Decode((new PacketList([skesk, seipd])).Encode());
        var decryptedSkesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var decryptedSeipd = ((SymEncryptedIntegrityProtectedData)packets[1]).DecryptWithSessionKey(decryptedSkesk.SessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadEaxDecryption()
    {
        var skeskData = "Bh4HAQsDCKWuV50fxdgr/2kiT5GZk7NQb6O1mmpzz/jF78X0HFf7VOHCJoFdeCj1+SxFTrZevgCrWYbGjm58VQ==";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(skesk.Aead, Is.EqualTo(AeadAlgorithm.Eax));
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("3881bafe985412459b86c36f98cb9a5e")));
        });

        var seipdData = "AgcBBp/5DjsyGWTzpCkTyNzGYZMlAVIn77fq6qSfBMLmdBddSj0ibtavy5yprBIsFHDhHGPUwKskHGqTitSL+ZpambkLuoMl3mEEdUAlireVmpWtBR3alusVQx3+9fXiJVyngmFUbjOa";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData));
        Assert.That(seipd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
        Assert.That(seipd.Aead, Is.EqualTo(AeadAlgorithm.Eax));
        
        var decryptedSeipd = seipd.DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadOcbDecryption()
    {
        var skeskData = "Bh0HAgsDCFaimNL142RT/8/MXBFmTtudtCWQ19xGsHJBthLDgSz/++oA8jR7JWQRI/iHrmDU/WFOCDfYGdNs";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(skesk.Aead, Is.EqualTo(AeadAlgorithm.Ocb));
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("28e79ab82397d3c63de24ac217d7b791")));
        });

        var seipdData = "AgcCBiCmYfcx/JowMrViMyYCfjpdjbV0jr7/CwxZENCezdZB/5/ThWJ1gDW8SXVM4b8//6fa0KO4EE9RM89CpBAKg+70yhtIAaiEa/QrzafIzp1l4hLzAcvNmP3K3mlKh3rUJHMj9uhX";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData));
        Assert.That(seipd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
        Assert.That(seipd.Aead, Is.EqualTo(AeadAlgorithm.Ocb));
        
        var decryptedSeipd = seipd.DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadGcmDecryption()
    {
        var skeskData = "BhoHAwsDCOnTl4WyBwAI/7QufEg+9IhEV8s3Jrmz25/3duX02aQJUuJEcpiFGr//dSbfLdVUQXV5p3mf";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(skesk.Aead, Is.EqualTo(AeadAlgorithm.Gcm));
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("1936fc8568980274bb900d8319360c77")));
        });

        var seipdData = "AgcDBvy5RJC8uYu9ydEGxgkCZpQPcuie3CG1WWsVdrEB7Q+f/G/G1lu/0k3NB5CWbm0ehaMAU3hMsdi2oGme8SFVp7KtYlhTG1dlH9d3eRL6leNdm0Ahb2mkwkjbKP9DMfFjKQc5nm/5";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData));
        Assert.That(seipd.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
        Assert.That(seipd.Aead, Is.EqualTo(AeadAlgorithm.Gcm));
        
        var decryptedSeipd = seipd.DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestEncryptedUsingAes128Argon2()
    {
        var skeskData = "BAcEnFL4PCf5XlDVNUQOzf8xNgEEFZ5S/K0izz+VZULLp5TvhAsR";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes128));
            Assert.That(skesk.S2k, Is.InstanceOf<Argon2S2K>());
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("01fe16bbacfd1e7b78ef3b865187374f")));
        });

        var seipdData = "AZgYpj5gnPi7oX4MOUME6vk1FBe38okh/ibiY6UrIL+6otumcslkydOrejv0bEFN0h07OEdd8DempXiZPMU=";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData)).DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)seipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestEncryptedUsingAes192Argon2()
    {
        var skeskData = "BAgE4UysRxU0WRipYtyjR+FD+AEEFYcyydr2txRvP6ZqSD3fx/5naFUuVQSy8Bc=";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes192));
            Assert.That(skesk.S2k, Is.InstanceOf<Argon2S2K>());
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("27006dae68e509022ce45a14e569e91001c2955af8dfe194")));
        });

        var seipdData = "AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRysLVg77Mwwfgl2n/d572WciAM=";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData)).DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)seipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void Test1EncryptedUsingAes265Argon2()
    {
        var skeskData = "BAkEuHiVICBv95nGiCxCRaZifAEEFZ2fZeyrWoHQpZvVGkP2ejP+a6JJUhqRrutt2Jml3sxo/A==";
        var skesk = (SymmetricKeyEncryptedSessionKey)SymmetricKeyEncryptedSessionKey.FromBytes(Base64.Decode(skeskData)).Decrypt(Passphrase);
        var sessionKey = skesk.SessionKey;
        Assert.Multiple(() =>
        {
            Assert.That(skesk.Symmetric, Is.EqualTo(SymmetricAlgorithm.Aes256));
            Assert.That(skesk.S2k, Is.InstanceOf<Argon2S2K>());
            Assert.That(sessionKey!.EncryptionKey, Is.EqualTo(Hex.Decode("bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0")));
        });

        var seipdData = "AfirtbIE3SaPO19Vq7qe5dMCcqWZbNtVMHeu5vZKBetHnnx/yveQ9brJYlzhJvGskCUJma43+iur/T1sKjE=";
        var seipd = SymEncryptedIntegrityProtectedData.FromBytes(Base64.Decode(seipdData)).DecryptWithSessionKey(sessionKey!);
        var literalData = (LiteralData)seipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestAeadEncryptSessionKey()
    {
        var sessionKey = SessionKey.ProduceKey(Config.PreferredSymmetric, Config.PreferredAead);
        var skesk = SymmetricKeyEncryptedSessionKey.EncryptSessionKey(Passphrase, sessionKey.Symmetric, sessionKey, sessionKey.Aead);
        Assert.That(skesk.Version, Is.EqualTo(6));
        Assert.That(skesk.Encrypted, Is.Not.Empty);

        var seipd = SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(skesk.SessionKey!,
            new PacketList([LiteralData.FromText(LiteralText)]), sessionKey.Aead);
        Assert.That(seipd.Version, Is.EqualTo(2));
        Assert.That(seipd.Encrypted, Is.Not.Empty);

        var packets = PacketList.Decode(new PacketList([skesk, seipd]).Encode());
        var decryptedSkesk = ((SymmetricKeyEncryptedSessionKey)packets[0]).Decrypt(Passphrase);
        var decryptedSeipd = ((SymEncryptedIntegrityProtectedData)packets[1]).DecryptWithSessionKey(decryptedSkesk.SessionKey!);
        var literalData = (LiteralData)decryptedSeipd.PacketList![0];
        Assert.That(literalData.Text, Is.EqualTo(LiteralText));
    }
}
