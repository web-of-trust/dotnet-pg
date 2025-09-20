// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Crypto;
using Enum;
using Type;
using Org.BouncyCastle.Security;

/// <summary>
///     Implementation of the Symmetrically Encrypted Authenticated Encryption with
///     Additional Data (AEAD) Protected Data Packet - Type 20
/// </summary>
public class AeadEncryptedData(
    SymmetricAlgorithm symmetric,
    AeadAlgorithm aead,
    int chunkSize,
    byte[] iv,
    byte[] encrypted,
    IPacketList? packetList = null)
    : BasePacket(PacketType.AeadEncryptedData), IAeadEncryptedDataPacket
{
    private const int Version = 1;
    private const int AeadTagLength = 16;

    public SymmetricAlgorithm Symmetric => symmetric;

    public AeadAlgorithm Aead => aead;

    public int ChunkSize => chunkSize;

    public byte[] Iv => iv;

    public byte[] Encrypted => encrypted;

    public IPacketList? PacketList => packetList;

    public IEncryptedDataPacket Encrypt(byte[] key, SymmetricAlgorithm sym = SymmetricAlgorithm.Aes256)
    {
        return PacketList != null ? EncryptPackets(key, PacketList, sym, aead) : this;
    }

    public IEncryptedDataPacket EncryptWithSessionKey(ISessionKey sessionKey)
    {
        return Encrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    public IEncryptedDataPacket Decrypt(
        byte[] key, SymmetricAlgorithm sym = SymmetricAlgorithm.Aes256
    )
    {
        if (packetList != null) return this;
        var length = encrypted.Length;
        var data = encrypted.Take(length - AeadTagLength).ToArray();
        var authTag = encrypted.Skip(length - AeadTagLength).ToArray();
        return new AeadEncryptedData(
            symmetric,
            aead,
            chunkSize,
            iv,
            encrypted,
            Packet.PacketList.Decode(
                Crypt(
                    false,
                    key,
                    data,
                    authTag,
                    iv,
                    symmetric,
                    aead,
                    chunkSize
                )
            )
        );
    }

    public IEncryptedDataPacket DecryptWithSessionKey(ISessionKey sessionKey)
    {
        return Decrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    /// <summary>
    ///     Read Aead encrypted data packet from bytes
    /// </summary>
    public static AeadEncryptedData FromBytes(byte[] bytes)
    {
        var offset = 0;
        // A one-octet version number.
        var version = bytes[offset++];
        if (version != Version)
            throw new ArgumentException(
                $"Version {version} of the AEPD is not supported."
            );

        var symmetric = (SymmetricAlgorithm)bytes[offset++];
        var aead = (AeadAlgorithm)bytes[offset++];
        var chunkSize = bytes[offset++];
        var ivLength = Helper.AeadIvLength(aead);
        var iv = bytes.Skip(offset).Take(ivLength).ToArray();
        offset += ivLength;
        var encrypted = bytes.Skip(offset).ToArray();
        return new AeadEncryptedData(symmetric, aead, chunkSize, iv, encrypted);
    }

    /// <summary>
    ///     Encrypt packet list
    /// </summary>
    public static AeadEncryptedData EncryptPackets(
        byte[] key,
        IPacketList packetList,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm aead = AeadAlgorithm.Gcm
    )
    {
        Helper.AssertSymmetric(symmetric);
        var chunkSize = Config.AeadChunkSize;
        var iv = SecureRandom.GetNextBytes(new SecureRandom(), Helper.AeadIvLength(aead));
        return new AeadEncryptedData(
            symmetric,
            aead,
            chunkSize,
            iv,
            Crypt(
                true,
                key,
                packetList.Encode(),
                [],
                iv,
                symmetric,
                aead,
                chunkSize
            ),
            packetList
        );
    }

    /// <summary>
    ///     Encrypt packet list with session key
    /// </summary>
    public static AeadEncryptedData EncryptPacketsWithSessionKey(
        ISessionKey sessionKey,
        IPacketList packetList,
        AeadAlgorithm aead = AeadAlgorithm.Gcm
    )
    {
        return EncryptPackets(
            sessionKey.EncryptionKey,
            packetList,
            sessionKey.Symmetric,
            aead
        );
    }

    public override byte[] ToBytes()
    {
        return
        [
            Version,
            (byte)symmetric,
            (byte)aead,
            (byte)chunkSize,
            ..iv,
            ..encrypted
        ];
    }

    private static byte[] Crypt(
        bool forEncryption,
        byte[] key,
        byte[] data,
        byte[] finalChunk,
        byte[] iv,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm aead = AeadAlgorithm.Gcm,
        int chunkSizeByte = 12
    )
    {
        var dataLength = data.Length;
        var tagLength = forEncryption ? 0 : AeadTagLength;
        var chunkSize = (1 << (chunkSizeByte + 6)) + tagLength;

        var adataBuffer = new byte[13];
        byte[] aData =
        [
            (int)PacketType.AeadEncryptedData | 0xc0,
            Version,
            (byte)symmetric,
            (byte)aead,
            (byte)chunkSizeByte
        ];
        Array.Copy(aData, 0, adataBuffer, 0, aData.Length);

        var processed = dataLength - tagLength * (int)Math.Ceiling((double)dataLength / chunkSize);
        var crypted = new byte[processed + (forEncryption ? AeadTagLength : 0)];
        var cipher = new AeadCipher(key, aead, symmetric);
        var chunkData = (byte[])data.Clone();
        for (var index = 0; index == 0 || chunkData.Length > 0;)
        {
            // We take a chunk of data, en/decrypt it,
            // and shift `data` to the next chunk.
            var chunkIndexData = adataBuffer.Skip(5).Take(8).ToArray();
            var size = chunkSize < chunkData.Length ? chunkSize : chunkData.Length;
            var nonce = cipher.GetNonce(iv, chunkIndexData);
            var cryptedData = forEncryption
                ? cipher.Encrypt(chunkData.Take(size).ToArray(), nonce, adataBuffer)
                : cipher.Decrypt(chunkData.Take(size).ToArray(), nonce, adataBuffer);
            Array.Copy(cryptedData, 0, crypted, index * size, cryptedData.Length);
            chunkData = chunkData.Skip(size).ToArray();
            Array.Copy(Helper.Pack32(++index), 0, adataBuffer, 9, 4);
        }

        // For encryption: empty final chunk
        // For decryption: final authentication tag
        var chunkIndex = adataBuffer.Skip(5).Take(8).ToArray();
        var adataTagBuffer = new byte[21];
        Array.Copy(adataBuffer, 0, adataTagBuffer, 0, adataBuffer.Length);
        Array.Copy(Helper.Pack32(processed), 0, adataTagBuffer, 17, 4);
        var finalCrypted = forEncryption
            ? cipher.Encrypt(
                finalChunk,
                cipher.GetNonce(iv, chunkIndex),
                adataTagBuffer
            )
            : cipher.Decrypt(
                finalChunk,
                cipher.GetNonce(iv, chunkIndex),
                adataTagBuffer
            );
        return [..crypted, ..finalCrypted];
    }
}