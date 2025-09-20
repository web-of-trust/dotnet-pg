// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Encrypted message interface.
/// </summary>
public interface IEncryptedMessage : IArmorable
{
    /// <summary>
    ///     Get encrypted packet.
    /// </summary>
    IEncryptedDataPacket EncryptedPacket { get; }

    /// <summary>
    ///     Get session key.
    /// </summary>
    ISessionKey? SessionKey { get; }

    /// <summary>
    ///     Decrypt the message.
    ///     One of `decryptionKeys` or `passwords` must be specified.
    /// </summary>
    ILiteralMessage Decrypt(IList<IKey> decryptionKeys, IList<string> passwords);
}