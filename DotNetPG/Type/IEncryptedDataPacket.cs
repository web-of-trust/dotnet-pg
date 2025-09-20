// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Encrypted data packet interface
/// </summary>
public interface IEncryptedDataPacket
{
    /// <summary>
    ///     Get encrypted data
    /// </summary>
    byte[] Encrypted { get; }

    /// <summary>
    ///     Get decrypted packets contained within.
    /// </summary>
    IPacketList? PacketList { get; }

    /// <summary>
    ///     Encrypt the payload in the packet.
    /// </summary>
    IEncryptedDataPacket Encrypt(
        byte[] key,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    );

    /// <summary>
    ///     Encrypt the payload in the packet with session key.
    /// </summary>
    IEncryptedDataPacket EncryptWithSessionKey(ISessionKey sessionKey);

    /// <summary>
    ///     Decrypt the encrypted data contained in the packet.
    /// </summary>
    IEncryptedDataPacket Decrypt(
        byte[] key,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    );

    /// <summary>
    ///     Encrypt the payload in the packet with session key.
    /// </summary>
    IEncryptedDataPacket DecryptWithSessionKey(ISessionKey sessionKey);
}