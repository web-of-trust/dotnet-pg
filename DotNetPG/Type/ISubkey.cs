// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Subkey interface
/// </summary>
public interface ISubkey : IPacketContainer
{
    /// <summary>
    ///     Get main key
    /// </summary>
    IKey MainKey { get; }

    /// <summary>
    ///     Get key packet
    /// </summary>
    ISubkeyPacket KeyPacket { get; }

    /// <summary>
    ///     Get key version
    /// </summary>
    int Version { get; }

    /// <summary>
    ///     Get the expiration time of the subkey or null if subkey does not expire.
    /// </summary>
    DateTime? ExpirationTime { get; }

    /// <summary>
    ///     Get creation time
    /// </summary>
    DateTime? CreationTime { get; }

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
    ///     Get key strength
    /// </summary>
    int KeyStrength { get; }

    /// <summary>
    ///     Get revocation signatures
    /// </summary>
    IList<ISignaturePacket> RevocationSignatures { get; }

    /// <summary>
    ///     Get binding signatures
    /// </summary>
    IList<ISignaturePacket> BindingSignatures { get; }

    /// <summary>
    ///     Return subkey is signing or verification key
    /// </summary>
    bool IsSigningKey { get; }

    /// <summary>
    ///     Return subkey is encryption or decryption key
    /// </summary>
    bool IsEncryptionKey { get; }

    /// <summary>
    ///     Check if a binding signature of a subkey is revoked
    /// </summary>
    bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify user.
    /// </summary>
    bool Verify(DateTime? time = null);

    /// <summary>
    ///     Revoke the subkey
    /// </summary>
    IUser RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );
}