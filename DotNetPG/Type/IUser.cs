// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     OpenPGP user interface
///     that represents a user ID or attribute packet and the relevant signatures.
/// </summary>
public interface IUser : IPacketContainer
{
    /// <summary>
    ///     Get main key
    /// </summary>
    IKey MainKey { get; }

    /// <summary>
    ///     Get user ID packet
    /// </summary>
    IUserIdPacket UserIdPacket { get; }

    /// <summary>
    ///     Get revocation signatures
    /// </summary>
    IReadOnlyList<ISignaturePacket> RevocationCertifications { get; }

    /// <summary>
    ///     Get self signatures
    /// </summary>
    IReadOnlyList<ISignaturePacket> SelfCertifications { get; }

    /// <summary>
    ///     Get other signatures
    /// </summary>
    IReadOnlyList<ISignaturePacket> OtherCertifications { get; }

    /// <summary>
    ///     Get user ID
    /// </summary>
    byte[] UserId { get; }

    /// <summary>
    ///     Return user is primary
    /// </summary>
    bool IsPrimary { get; }

    /// <summary>
    ///     Check if a given certificate of the user is revoked.
    /// </summary>
    bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify user is certified.
    /// </summary>
    bool IsCertified(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify user.
    /// </summary>
    bool Verify(DateTime? time = null);

    /// <summary>
    ///     Generate third-party certification over this user and its primary key.
    /// </summary>
    IUser CertifyBy(IPrivateKey signKey, DateTime? time = null);

    /// <summary>
    ///     Revoke the user & return clone user with new revocation signature.
    /// </summary>
    IUser RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );
}