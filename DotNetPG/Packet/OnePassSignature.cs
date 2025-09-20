// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Type;

/// <summary>
///     Implementation an OpenPGP One-Pass Signature packet (Tag 4).
/// </summary>
public class OnePassSignature(
    int version,
    SignatureType signatureType,
    HashAlgorithm hashAlgorithm,
    KeyAlgorithm keyAlgorithm,
    byte[] salt,
    byte[] issuerFingerprint,
    byte[] issuerKeyId,
    int nested = 0)
    : BasePacket(PacketType.OnePassSignature)
{
    private const int Version3 = 3;
    private const int Version6 = 6;

    public int Version => version;

    public SignatureType SignatureType => signatureType;

    public HashAlgorithm HashAlgorithm => hashAlgorithm;

    public KeyAlgorithm KeyAlgorithm => keyAlgorithm;

    public byte[] Salt => salt;

    public byte[] IssuerFingerprint => issuerFingerprint;

    public byte[] IssuerKeyId => issuerKeyId;

    public int Nested => nested;

    /// <summary>
    ///     Read One-Pass Signature packet from bytes
    /// </summary>
    public static OnePassSignature FromBytes(byte[] bytes)
    {
        var offset = 0;
        // A one-octet version number.
        var version = bytes[offset++];
        if (version != Version3 && version != Version6)
            throw new ArgumentException(
                $"Version {version} of the one-pass signature packet is unsupported."
            );

        // A one-octet signature type.
        var signatureType = (SignatureType)bytes[offset++];

        // A one-octet number describing the hash algorithm used.
        var hashAlgorithm = (HashAlgorithm)bytes[offset++];

        // A one-octet number describing the public-key algorithm used.
        var keyAlgorithm = (KeyAlgorithm)bytes[offset++];

        byte[] salt = [];
        byte[] fingerprint = [];
        byte[] keyId;

        if (version == Version6)
        {
            var saltLength = bytes[offset++];
            salt = bytes.Skip(offset).Take(saltLength).ToArray();
            offset += saltLength;

            fingerprint = bytes.Skip(offset).Take(32).ToArray();
            offset += 32;
            keyId = fingerprint.Take(PublicKey.KeyIdSize).ToArray();
        }
        else
        {
            keyId = bytes.Skip(offset).Take(PublicKey.KeyIdSize).ToArray();
            offset += 8;
        }

        // A one-octet number holding a flag showing whether the signature is nested.
        var nested = bytes[offset];

        return new OnePassSignature(
            version,
            signatureType,
            hashAlgorithm,
            keyAlgorithm,
            salt,
            fingerprint,
            keyId,
            nested
        );
    }

    /// <summary>
    ///     Build one-pass signature packet from signature packet
    /// </summary>
    public static OnePassSignature FromSignature(
        ISignaturePacket signature, int nested = 0
    )
    {
        return new OnePassSignature(
            signature.Version == Version6 ? Version6 : Version3,
            signature.SignatureType,
            signature.HashAlgorithm,
            signature.KeyAlgorithm,
            signature.Salt,
            signature.IssuerFingerprint,
            signature.IssuerKeyId,
            nested
        );
    }

    public override byte[] ToBytes()
    {
        var isV6 = version == Version6;
        byte[] bytes =
        [
            isV6 ? (byte)Version6 : (byte)Version3,
            (byte)signatureType,
            (byte)hashAlgorithm,
            (byte)keyAlgorithm
        ];
        if (isV6)
            bytes =
            [
                ..bytes,
                (byte)salt.Length,
                ..salt,
                ..issuerFingerprint,
                (byte)nested
            ];
        else
            bytes =
            [
                ..bytes,
                ..issuerKeyId,
                (byte)nested
            ];
        return bytes;
    }
}