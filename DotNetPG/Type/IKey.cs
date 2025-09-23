// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     OpenPGP Key interface.
/// </summary>
public interface IKey : IArmorable, IPacketContainer
{
    /// <summary>
    ///     Get key packet.
    /// </summary>
    IKeyPacket KeyPacket { get; }

    /// <summary>
    ///     Get key as public key
    /// </summary>
    IKey PublicKey { get; }

    /// <summary>
    ///     Get key version
    /// </summary>
    int Version { get; }

    /// <summary>
    ///     Get the expiration time of the key or null if key does not expire.
    /// </summary>
    DateTime? ExpirationTime { get; }

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
    ///     Get key strength
    /// </summary>
    int KeyStrength { get; }

    /// <summary>
    ///     Get revocation signatures
    /// </summary>
    ISignaturePacket[] RevocationSignatures { get; }

    /// <summary>
    ///     Get direct signatures
    /// </summary>
    ISignaturePacket[] DirectSignatures { get; }

    /// <summary>
    ///     Get users
    /// </summary>
    IUser[] Users { get; }

    /// <summary>
    ///     Get subkeys
    /// </summary>
    ISubkey[] Subkeys { get; }

    /// <summary>
    ///     Get primary user
    /// </summary>
    IUser? PrimaryUser { get; }

    /// <summary>
    ///     Return key is private
    /// </summary>
    bool IsPrivate { get; }

    /// <summary>
    ///     Return preferred symmetrics
    /// </summary>
    SymmetricAlgorithm[] PreferredSymmetrics { get; }

    /// <summary>
    ///     Return AEAD is supported
    /// </summary>
    bool AeadSupported { get; }

    /// <summary>
    ///     Return preferred aeads by given symmetric
    /// </summary>
    AeadAlgorithm[] PreferredAeads(SymmetricAlgorithm symmetric);

    /// <summary>
    ///     The key is revoked.
    /// </summary>
    bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    );

    /// <summary>
    ///     The key is certified.
    /// </summary>
    bool IsCertified(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify key.
    /// </summary>
    bool Verify(DateTime? time = null);

    /// <summary>
    ///     Certify by private key.
    /// </summary>
    IKey CertifyBy(IPrivateKey signKey, DateTime? time = null);

    /// <summary>
    ///     Revoke by private key.
    /// </summary>
    IKey RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );
}