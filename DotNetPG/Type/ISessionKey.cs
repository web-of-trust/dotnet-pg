// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Session key interface
/// </summary>
public interface ISessionKey
{
    /// <summary>
    ///     Get encryption key
    /// </summary>
    byte[] EncryptionKey { get; }

    /// <summary>
    ///     Get symmetric algorithm to encrypt the message with
    /// </summary>
    SymmetricAlgorithm Symmetric { get; }

    /// <summary>
    ///     Get AEAD algorithm to encrypt the message with
    /// </summary>
    AeadAlgorithm? Aead { get; }

    /// <summary>
    ///     Checksum the encryption key
    /// </summary>
    ISessionKey Checksum(byte[] checksum);

    /// <summary>
    ///     Compute checksum
    /// </summary>
    byte[] ComputeChecksum();

    /// <summary>
    ///     Serialize session key to bytes
    /// </summary>
    byte[] ToBytes();
}