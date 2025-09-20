// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Packet type enum
///     A list of packet types and numeric tags associated with them.
/// </summary>
public enum PacketType
{
    /// <summary>
    ///     PKESK - Public Key Encrypted Session Key Packet
    /// </summary>
    PublicKeyEncryptedSessionKey = 1,

    /// <summary>
    ///     SIG - Signature Packet
    /// </summary>
    Signature = 2,

    /// <summary>
    ///     SKESK - Symmetric Key Encrypted Session Key Packet
    /// </summary>
    SymmetricKeyEncryptedSessionKey = 3,

    /// <summary>
    ///     OPS - One-Pass Signature Packet
    /// </summary>
    OnePassSignature = 4,

    /// <summary>
    ///     SECKEY - Secret Key Packet
    /// </summary>
    SecretKey = 5,

    /// <summary>
    ///     PUBKEY - Public Key Packet
    /// </summary>
    PublicKey = 6,

    /// <summary>
    ///     SECSUBKEY - Secret Subkey Packet
    /// </summary>
    SecretSubkey = 7,

    /// <summary>
    ///     COMP - Compressed Data Packet
    /// </summary>
    CompressedData = 8,

    /// <summary>
    ///     SED - Symmetrically Encrypted Data Packet
    /// </summary>
    SymEncryptedData = 9,

    /// <summary>
    ///     MARKER - Marker Packet
    /// </summary>
    Marker = 10,

    /// <summary>
    ///     LIT - Literal Data Packet
    /// </summary>
    LiteralData = 11,

    /// <summary>
    ///     TRUST - Trust Packet
    /// </summary>
    Trust = 12,

    /// <summary>
    ///     UID - User ID Packet
    /// </summary>
    UserId = 13,

    /// <summary>
    ///     PUBSUBKEY - Public Subkey Packet
    /// </summary>
    PublicSubkey = 14,

    /// <summary>
    ///     PUBSUBKEY - Public Subkey Packet
    /// </summary>
    UserAttribute = 17,

    /// <summary>
    ///     SEIPD - Symmetrically Encrypted and Integrity Protected Data Packet
    /// </summary>
    SymEncryptedIntegrityProtectedData = 18,

    /// <summary>
    ///     MDC - Modification Detection Code Packet
    /// </summary>
    ModificationDetectionCode = 19,

    /// <summary>
    ///     AEPD - Aead Encrypted Protected Data Packet
    /// </summary>
    AeadEncryptedData = 20,

    /// <summary>
    ///     PADDING - Padding Packet
    /// </summary>
    Padding = 21
}