// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Aead encrypted data packet interface.
/// </summary>
public interface IAeadEncryptedDataPacket : IEncryptedDataPacket
{
    /// <summary>
    ///     Get symmetric algorithm
    /// </summary>
    SymmetricAlgorithm Symmetric { get; }

    /// <summary>
    ///     Get AEAD algorithm
    /// </summary>
    AeadAlgorithm Aead { get; }

    /// <summary>
    ///     Get chunk size byte
    /// </summary>
    int ChunkSize { get; }

    /// <summary>
    ///     Get iv
    /// </summary>
    byte[] Iv { get; }
}