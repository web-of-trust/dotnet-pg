// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
/// Decryptor interface
/// </summary>
public interface IDecryptor
{
    /// <summary>
    /// Decrypt an encrypted message
    /// </summary>
    ILiteralMessage Decrypt(IEncryptedMessage message);

    /// <summary>
    /// Decrypt a armored encrypted string
    /// </summary>
    ILiteralMessage Decrypt(string messageData);

    /// <summary>
    /// Bulk decrypt encrypted messages
    /// </summary>
    IList<ILiteralMessage> BulkDecrypt(IList<IEncryptedMessage> messages);

    /// <summary>
    /// Decrypt encrypted session keys.
    /// </summary>
    ISessionKey DecryptSessionKey(IPacketList packetList);

    /// <summary>
    /// Decrypt encrypted session keys.
    /// </summary>
    ISessionKey DecryptSessionKey(IList<IEncryptedSessionKey> eskPackets);
}
