// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Secret key packet interface
/// </summary>
public interface ISecretKeyPacket : IKeyPacket
{
    /// <summary>
    ///     Get public key packet
    /// </summary>
    IPublicKeyPacket PublicKey { get; }

    /// <summary>
    ///     Get secret key material
    /// </summary>
    IKeyMaterial? SecretKeyMaterial { get; }

    /// <summary>
    ///     Get Symmetric algorithm
    /// </summary>
    SymmetricAlgorithm? Symmetric { get; }

    /// <summary>
    ///     Get AEAD algorithm
    /// </summary>
    AeadAlgorithm? Aead { get; }

    /// <summary>
    ///     Get s2k usage
    /// </summary>
    S2kUsage S2kUsage { get; }

    /// <summary>
    ///     Get string 2 key
    /// </summary>
    IString2Key? S2k { get; }

    /// <summary>
    ///     Return secret key packet is encrypted
    /// </summary>
    bool IsEncrypted { get; }

    /// <summary>
    ///     Return secret key packet is decrypted
    /// </summary>
    bool IsDecrypted { get; }

    /// <summary>
    ///     Encrypt secret key packet with passphrase
    /// </summary>
    ISecretKeyPacket Encrypt(
        string passphrase,
        SymmetricAlgorithm algorithm = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    );

    /// <summary>
    ///     Decrypt secret key packet with passphrase
    /// </summary>
    ISecretKeyPacket Decrypt(string passphrase);
}