// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Crypto;
using Enum;
using Type;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Implementation of the Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
/// </summary>
public class SymEncryptedIntegrityProtectedData : BasePacket, IEncryptedDataPacket
{
    private const int Version1 = 1;
    private const int Version2 = 2;
    private const int SaltSize = 32;
    private const int AeadTagLength = 16;

    public SymEncryptedIntegrityProtectedData(
        int version,
        byte[] encrypted,
        byte[] salt,
        int chunkSize = 0,
        SymmetricAlgorithm? symmetric = null,
        AeadAlgorithm? aead = null,
        IPacketList? packetList = null
    ) : base(PacketType.SymEncryptedIntegrityProtectedData)
    {
        Version = version;
        Encrypted = encrypted;
        Salt = salt;
        ChunkSize = chunkSize;
        Symmetric = symmetric;
        Aead = aead;
        PacketList = packetList;

        if (symmetric != null) Helper.AssertSymmetric(symmetric);

        if (aead != null)
        {
            if (version == Version1)
                throw new ArgumentException(
                    $"Using AEAD with v{version} SEIPD packet is not allowed."
                );
            if (salt.Length > 0 && salt.Length != SaltSize)
                throw new ArgumentException(
                    $"Salt size must be {SaltSize} bytes."
                );
            if (chunkSize <= 0)
                throw new ArgumentException(
                    "Chunk size must be greater than zero."
                );
        }
    }

    public int Version { get; }

    public byte[] Salt { get; }

    public int ChunkSize { get; }

    public SymmetricAlgorithm? Symmetric { get; }

    public AeadAlgorithm? Aead { get; }

    public byte[] Encrypted { get; }

    public IPacketList? PacketList { get; }

    public IEncryptedDataPacket Encrypt(
        byte[] key, SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        return PacketList != null ? EncryptPackets(key, PacketList, symmetric, Aead) : this;
    }

    public IEncryptedDataPacket EncryptWithSessionKey(ISessionKey sessionKey)
    {
        return Encrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    public IEncryptedDataPacket Decrypt(
        byte[] key, SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        if (PacketList != null) return this;
        var cipherSymmetric = Symmetric ?? symmetric;
        byte[] packetBytes;
        if (Aead != null)
        {
            var length = Encrypted.Length;
            var data = Encrypted.Take(length - AeadTagLength).ToArray();
            var authTag = Encrypted.Skip(length - AeadTagLength).ToArray();
            packetBytes = AeadCrypt(
                false,
                key,
                data,
                authTag,
                cipherSymmetric,
                (AeadAlgorithm)Aead,
                ChunkSize,
                Salt
            );
        }
        else
        {
            var blockSize = Helper.SymmetricBlockSize(cipherSymmetric);
            var cipher = new BufferedCipher(Helper.CfbCipherEngine(cipherSymmetric));
            cipher.Init(
                false,
                new ParametersWithIV(
                    new KeyParameter(key),
                    new byte[blockSize]
                )
            );
            var decrypted = cipher.Process(Encrypted);
            var digestSize = Helper.HashDigestSize(HashAlgorithm.Sha1);
            var realHash = decrypted.Skip(decrypted.Length - digestSize).ToArray();
            var toHash = decrypted.Take(decrypted.Length - digestSize).ToArray();
            var verifyHash = DigestUtilities.CalculateDigest(nameof(HashAlgorithm.Sha1), toHash);
            if (!Arrays.AreEqual(realHash, verifyHash)) throw new Exception("Modification detected.");
            packetBytes = toHash.Skip(blockSize + 2).Take(toHash.Length - blockSize - 4).ToArray();
        }

        return new SymEncryptedIntegrityProtectedData(
            Version, Encrypted, Salt, ChunkSize, cipherSymmetric, Aead, Packet.PacketList.Decode(packetBytes)
        );
    }

    public IEncryptedDataPacket DecryptWithSessionKey(ISessionKey sessionKey)
    {
        return Decrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    /// <summary>
    ///     Read SEIPD packet from bytes
    /// </summary>
    public static SymEncryptedIntegrityProtectedData FromBytes(byte[] bytes)
    {
        var offset = 0;
        // A one-octet version number.
        var version = bytes[offset++];
        if (version == Version1)
            return new SymEncryptedIntegrityProtectedData(
                version, bytes.Skip(offset).ToArray(), []
            );

        // - A one-octet symmetric algorithm.
        var symmetric = (SymmetricAlgorithm)bytes[offset++];

        // - A one-octet AEAD algorithm.
        var aead = (AeadAlgorithm)bytes[offset++];

        var chunkSize = bytes[offset++];

        var salt = bytes.Skip(offset).Take(SaltSize).ToArray();
        offset += SaltSize;

        return new SymEncryptedIntegrityProtectedData(
            version, bytes.Skip(offset).ToArray(), salt, chunkSize, symmetric, aead
        );
    }

    /// <summary>
    ///     Encrypt packet list
    /// </summary>
    public static SymEncryptedIntegrityProtectedData EncryptPackets(
        byte[] key,
        IPacketList packetList,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        Helper.AssertSymmetric(symmetric);
        var aeadProtect = aead != null;
        var version = aeadProtect ? Version2 : Version1;
        var salt = aeadProtect ? SecureRandom.GetNextBytes(new SecureRandom(), SaltSize) : [];
        var chunkSize = aeadProtect ? Config.AeadChunkSize : 0;

        byte[] encrypted;
        if (aeadProtect)
        {
            encrypted = AeadCrypt(
                true,
                key,
                packetList.Encode(),
                [],
                symmetric,
                (AeadAlgorithm)aead!,
                chunkSize,
                salt
            );
        }
        else
        {
            var cipher = new BufferedCipher(Helper.CfbCipherEngine(symmetric));
            cipher.Init(
                true,
                new ParametersWithIV(
                    new KeyParameter(key),
                    new byte[Helper.SymmetricBlockSize(symmetric)]
                )
            );
            byte[] toHash =
            [
                ..Helper.GeneratePrefix(symmetric), ..packetList.Encode(), 0xd3, 0x14
            ];
            encrypted = cipher.Process([
                ..toHash,
                ..DigestUtilities.CalculateDigest(
                    nameof(HashAlgorithm.Sha1).ToUpper(), toHash
                )
            ]);
        }

        return new SymEncryptedIntegrityProtectedData(
            version, encrypted, salt, chunkSize, symmetric, aead, packetList
        );
    }

    /// <summary>
    ///     Encrypt packet list with session key
    /// </summary>
    public static SymEncryptedIntegrityProtectedData EncryptPacketsWithSessionKey(
        ISessionKey sessionKey, IPacketList packetList, AeadAlgorithm? aead = null
    )
    {
        return EncryptPackets(sessionKey.EncryptionKey, packetList, sessionKey.Symmetric, aead);
    }

    public override byte[] ToBytes()
    {
        if (Version == Version2)
            return
            [
                (byte)Version,
                (byte)Symmetric!,
                (byte)Aead!,
                (byte)ChunkSize,
                ..Salt,
                ..Encrypted
            ];
        return
        [
            (byte)Version,
            ..Encrypted
        ];
    }

    private static byte[] AeadCrypt(
        bool forEncryption,
        byte[] key,
        byte[] data,
        byte[] finalChunk,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm aead = AeadAlgorithm.Gcm,
        int chunkSizeByte = 12,
        byte[]? salt = null
    )
    {
        var dataLength = data.Length;
        var tagLength = forEncryption ? 0 : AeadTagLength;
        var chunkSize = (1 << (chunkSizeByte + 6)) + tagLength;

        byte[] aData =
        [
            (int)PacketType.SymEncryptedIntegrityProtectedData | 0xc0,
            Version2,
            (byte)symmetric,
            (byte)aead,
            (byte)chunkSizeByte
        ];
        var keySize = (Helper.SymmetricKeySize(symmetric) + 7) >> 3;
        var ivLength = Helper.AeadIvLength(aead);
        var derivedKey = Helper.Hkdf(
            key, keySize + ivLength, HashAlgorithm.Sha256, salt, aData
        );
        var kek = derivedKey.Take(keySize).ToArray();
        var nonce = derivedKey.Skip(keySize).Take(ivLength).ToArray();
        // The last 8 bytes of HKDF output are unneeded, but this avoids one copy.
        Array.Clear(nonce, nonce.Length - 8, 8);

        var processed = dataLength - tagLength * (int)Math.Ceiling((double)dataLength / chunkSize);
        var crypted = new byte[processed + (forEncryption ? AeadTagLength : 0)];
        var cipher = new AeadCipher(kek, aead, symmetric);
        var chunkData = (byte[])data.Clone();
        for (var index = 0; index == 0 || chunkData.Length > 0;)
        {
            // Take a chunk of `data`, en/decrypt it,
            // and shift `data` to the next chunk.
            var size = chunkSize < chunkData.Length ? chunkSize : chunkData.Length;
            var cryptedData = forEncryption
                ? cipher.Encrypt(chunkData.Take(size).ToArray(), nonce, aData)
                : cipher.Decrypt(chunkData.Take(size).ToArray(), nonce, aData);
            Array.Copy(cryptedData, 0, crypted, index * size, cryptedData.Length);
            chunkData = chunkData.Skip(size).ToArray();
            Array.Copy(Helper.Pack32(++index), 0, nonce, ivLength - 4, 4);
        }

        // For encryption: empty final chunk
        // For decryption: final authentication tag
        byte[] aDataTag = [..aData, ..new byte[8]];
        Array.Copy(Helper.Pack32(processed), 0, aDataTag, aDataTag.Length - 4, 4);
        var finalCrypted = forEncryption
            ? cipher.Encrypt(
                finalChunk,
                nonce,
                aDataTag
            )
            : cipher.Decrypt(
                finalChunk,
                nonce,
                aDataTag
            );
        return [..crypted, ..finalCrypted];
    }
}