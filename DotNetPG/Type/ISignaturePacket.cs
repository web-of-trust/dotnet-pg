// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Signature packet interface.
/// </summary>
public interface ISignaturePacket : IPacket
{
    /// <summary>
    ///     Get version
    /// </summary>
    int Version { get; }

    /// <summary>
    ///     Get signature type
    /// </summary>
    SignatureType SignatureType { get; }

    /// <summary>
    ///     Get key algorithm
    /// </summary>
    KeyAlgorithm KeyAlgorithm { get; }

    /// <summary>
    ///     Get hash algorithm
    /// </summary>
    HashAlgorithm HashAlgorithm { get; }

    /// <summary>
    ///     Get hashed sub packets
    /// </summary>
    IList<ISubPacket> HashedSubpackets { get; }

    /// <summary>
    ///     Get unhashed sub packets
    /// </summary>
    IList<ISubPacket> UnhashedSubpackets { get; }

    /// <summary>
    ///     Get signature data
    /// </summary>
    byte[] SignatureData { get; }

    /// <summary>
    ///     Get signed hash value
    /// </summary>
    byte[] SignedHashValue { get; }

    /// <summary>
    ///     Get salt value
    /// </summary>
    byte[] Salt { get; }

    /// <summary>
    ///     Get signature
    /// </summary>
    byte[] Signature { get; }

    /// <summary>
    ///     Get signature creation time
    /// </summary>
    DateTime? CreationTime { get; }

    /// <summary>
    ///     Get signature expiration time
    /// </summary>
    DateTime? ExpirationTime { get; }

    /// <summary>
    ///     Get key expiration time
    /// </summary>
    int KeyExpirationTime { get; }

    /// <summary>
    ///     Get issuer key ID
    /// </summary>
    byte[] IssuerKeyId { get; }

    /// <summary>
    ///     Get issuer key fingerprint
    /// </summary>
    byte[] IssuerFingerprint { get; }

    /// <summary>
    ///     Return is primary user ID
    /// </summary>
    bool IsPrimaryUserId { get; }

    /// <summary>
    ///     Return is certification
    /// </summary>
    bool IsCertification { get; }

    /// <summary>
    ///     Return is revocation certification
    /// </summary>
    bool IsCertRevocation { get; }

    /// <summary>
    ///     Return is direct key
    /// </summary>
    bool IsDirectKey { get; }

    /// <summary>
    ///     Return is key revocation
    /// </summary>
    bool IsKeyRevocation { get; }

    /// <summary>
    ///     Return is subkey binding
    /// </summary>
    bool IsSubkeyBinding { get; }

    /// <summary>
    ///     Return is subkey revocation
    /// </summary>
    bool IsSubkeyRevocation { get; }

    /// <summary>
    ///     Get sub packet
    /// </summary>
    T? GetSubPacket<T>() where T : ISubPacket;

    /// <summary>
    ///     Verify signature expiration date
    /// </summary>
    bool IsExpired(DateTime? time = null);

    /// <summary>
    ///     Verify the signature packet.
    /// </summary>
    bool Verify(
        IKeyPacket verifyKey,
        byte[] dataToVerify,
        DateTime? time = null
    );
}