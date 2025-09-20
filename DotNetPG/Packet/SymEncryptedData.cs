// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Crypto;
using Enum;
using Type;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
///     SymEncryptedData packet (tag 9) represents a Symmetrically Encrypted Data packet.
/// </summary>
public class SymEncryptedData(byte[] encrypted, IPacketList? packetList = null)
    : BasePacket(PacketType.SymEncryptedData), IEncryptedDataPacket
{
    public byte[] Encrypted => encrypted;

    public IPacketList? PacketList => packetList;

    public IEncryptedDataPacket Encrypt(
        byte[] key, SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        return packetList != null ? EncryptPackets(key, packetList, symmetric) : this;
    }

    public IEncryptedDataPacket EncryptWithSessionKey(ISessionKey sessionKey)
    {
        return Encrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    public IEncryptedDataPacket Decrypt(
        byte[] key, SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        if (!Config.AllowUnauthenticated)
            throw new Exception(
                "Decrypt an unauthenticated packet is not allowed."
            );
        var cipher = new BufferedCipher(Helper.CfbCipherEngine(symmetric));
        var blockSize = Helper.SymmetricBlockSize(symmetric);
        cipher.Init(
            false,
            new ParametersWithIV(
                new KeyParameter(key),
                encrypted.Skip(2).Take(blockSize).ToArray()
            )
        );
        return new SymEncryptedData(
            encrypted,
            Packet.PacketList.Decode(
                cipher.Process(encrypted.Skip(blockSize + 2).ToArray())
            )
        );
    }

    public IEncryptedDataPacket DecryptWithSessionKey(ISessionKey sessionKey)
    {
        return Decrypt(sessionKey.EncryptionKey, sessionKey.Symmetric);
    }

    /// <summary>
    ///     Read Symmetrically Encrypted Data packet from bytes
    /// </summary>
    public static SymEncryptedData FromBytes(byte[] bytes)
    {
        return new SymEncryptedData(bytes);
    }

    /// <summary>
    ///     Encrypt packet list
    /// </summary>
    public static SymEncryptedData EncryptPackets(
        byte[] key,
        IPacketList packetList,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        Helper.AssertSymmetric(symmetric);
        var cipher = new BufferedCipher(Helper.CfbCipherEngine(symmetric));
        cipher.Init(
            true,
            new ParametersWithIV(
                new KeyParameter(key),
                new byte[Helper.SymmetricBlockSize(symmetric)]
            )
        );

        var prefix = cipher.Process(Helper.GeneratePrefix(symmetric));
        cipher.Init(
            true,
            new ParametersWithIV(
                new KeyParameter(key),
                prefix.Skip(2).ToArray()
            )
        );
        return new SymEncryptedData(
            [..prefix, ..cipher.Process(packetList.Encode())], packetList
        );
    }

    public override byte[] ToBytes()
    {
        return encrypted;
    }
}