// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Key packet interface.
/// </summary>
public interface IKeyPacket : ISigning, IPacket
{
    /// <summary>
    ///     Get key version
    /// </summary>
    int Version { get; }

    /// <summary>
    ///     Get creation time
    /// </summary>
    DateTime CreationTime { get; }

    /// <summary>
    ///     Get key algorithm
    /// </summary>
    KeyAlgorithm KeyAlgorithm { get; }

    /// <summary>
    ///     Get fingerprint
    /// </summary>
    byte[] Fingerprint { get; }

    /// <summary>
    ///     Get key ID
    /// </summary>
    byte[] KeyId { get; }

    /// <summary>
    ///     Get key length
    /// </summary>
    int KeyLength { get; }

    /// <summary>
    ///     Is signing key
    /// </summary>
    bool IsSigningKey { get; }

    /// <summary>
    ///     Is encryption key
    /// </summary>
    bool IsEncryptionKey { get; }

    /// <summary>
    ///     Is version 6
    /// </summary>
    bool IsV6Key { get; }

    /// <summary>
    ///     Get key material
    /// </summary>
    IKeyMaterial KeyMaterial { get; }

    /// <summary>
    ///     Get preferred hash algorithm
    /// </summary>
    HashAlgorithm GetPreferredHash(HashAlgorithm? algorithm = null);
}