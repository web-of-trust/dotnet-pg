// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Symmetric key encrypted session key interface.
/// </summary>
public interface ISymmetricKeyEncryptedSessionKey : IEncryptedSessionKey, IPacket
{
    int Version { get; }

    IString2Key S2k { get; }

    SymmetricAlgorithm Symmetric { get; }

    AeadAlgorithm? Aead { get; }

    byte[] Iv { get; }

    byte[] Encrypted { get; }

    /// <summary>
    ///     Decrypt session key
    /// </summary>
    IEncryptedSessionKey Decrypt(string password);
}
