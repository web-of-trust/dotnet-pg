// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Signature sub packet type
/// </summary>
public enum SignatureSubPacketType
{
    SignatureCreationTime = 2,
    SignatureExpirationTime = 3,
    ExportableCertification = 4,
    TrustSignature = 5,
    RegularExpression = 6,
    Revocable = 7,
    KeyExpirationTime = 9,
    PlaceholderBackwardCompatibility = 10,
    PreferredSymmetricAlgorithms = 11,
    RevocationKey = 12,
    IssuerKeyId = 16,
    NotationData = 20,
    PreferredHashAlgorithms = 21,
    PreferredCompressionAlgorithms = 22,
    KeyServerPreferences = 23,
    PreferredKeyServer = 24,
    PrimaryUserId = 25,
    PolicyUri = 26,
    KeyFlags = 27,
    SignerUserId = 28,
    RevocationReason = 29,
    Features = 30,
    SignatureTarget = 31,
    EmbeddedSignature = 32,
    IssuerFingerprint = 33,
    PreferredAeadAlgorithms = 34,
    IntendedRecipientFingerprint = 35,
    AttestedCertifications = 37,
    KeyBlock = 38,
    PreferredAeadCiphers = 39
}