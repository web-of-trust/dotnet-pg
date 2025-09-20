// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Key;
using Type;
using System.Buffers.Binary;
using Org.BouncyCastle.Security;

/// <summary>
///     Implementation an OpenPGP public key packet (Tag 6).
/// </summary>
public class PublicKey : BasePacket, IPublicKeyPacket
{
    public const int KeyIdSize = 8;

    public PublicKey(
        int version,
        DateTime creationTime,
        KeyAlgorithm keyAlgorithm,
        IKeyMaterial keyMaterial
    ) : base(PacketType.PublicKey)
    {
        Version = version;
        CreationTime = creationTime;
        KeyAlgorithm = keyAlgorithm;
        KeyMaterial = keyMaterial;

        if (Version != (int)KeyVersion.V4 && Version != (int)KeyVersion.V6)
            throw new ArgumentException("Invalid key version.");
        Helper.AssertKeyAlgorithm(KeyAlgorithm);
        switch (KeyAlgorithm)
        {
            case KeyAlgorithm.RsaEncrypt:
            case KeyAlgorithm.RsaGeneral:
            case KeyAlgorithm.RsaSign:
                if (KeyMaterial.KeyLength < (int)RsaKeySize.Normal)
                    throw new ArgumentException("Invalid RSA key length.");
                break;
        }

        if (IsV6Key && KeyMaterial is EcPublicKeyMaterial { Curve: EcCurve.Curve25519 or EcCurve.Ed25519 })
            throw new ArgumentException(
                "Legacy curve cannot be used with v6 key packet."
            );

        if (IsV6Key)
        {
            Fingerprint = DigestUtilities.CalculateDigest(
                "SHA256", SignBytes()
            );
            KeyId = Fingerprint.Take(KeyIdSize).ToArray();
        }
        else
        {
            Fingerprint = DigestUtilities.CalculateDigest(
                "SHA1", SignBytes()
            );
            KeyId = Fingerprint.Skip(12).Take(KeyIdSize).ToArray();
        }
    }

    public int Version { get; }

    public DateTime CreationTime { get; }

    public KeyAlgorithm KeyAlgorithm { get; }

    public IKeyMaterial KeyMaterial { get; }

    public byte[] Fingerprint { get; }

    public byte[] KeyId { get; }

    public int KeyLength => KeyMaterial.KeyLength;

    public bool IsSigningKey => KeyAlgorithm switch
    {
        KeyAlgorithm.RsaEncrypt or
            KeyAlgorithm.ElGamal or
            KeyAlgorithm.EcDh or
            KeyAlgorithm.DiffieHellman or
            KeyAlgorithm.AeDh or
            KeyAlgorithm.X25519 or
            KeyAlgorithm.X448 => false,
        _ => true
    };

    public bool IsEncryptionKey => KeyAlgorithm switch
    {
        KeyAlgorithm.RsaSign or
            KeyAlgorithm.Dsa or
            KeyAlgorithm.EcDsa or
            KeyAlgorithm.EdDsaLegacy or
            KeyAlgorithm.AeDsa or
            KeyAlgorithm.Ed25519 or
            KeyAlgorithm.Ed448 => false,
        _ => true
    };

    public bool IsV6Key => Version == (int)KeyVersion.V6;

    public HashAlgorithm GetPreferredHash(HashAlgorithm? algorithm = null)
    {
        if (KeyMaterial is EcPublicKeyMaterial material) return Helper.EcCurveHash(material.Curve);

        return KeyAlgorithm switch
        {
            KeyAlgorithm.Ed25519 => HashAlgorithm.Sha256,
            KeyAlgorithm.Ed448 => HashAlgorithm.Sha512,
            _ => algorithm ?? Config.PreferredHash
        };
    }

    public override byte[] ToBytes()
    {
        var dto = new DateTimeOffset(CreationTime);
        var kmBytes = KeyMaterial.ToBytes();
        return
        [
            (byte)Version,
            ..Helper.Pack32((int)dto.ToUnixTimeSeconds()),
            (byte)KeyAlgorithm,
            ..Version == (int)KeyVersion.V6 ? Helper.Pack32(kmBytes.Length) : [],
            ..kmBytes
        ];
    }

    public byte[] SignBytes()
    {
        var bytes = ToBytes();
        return
        [
            (byte)(Version + 0x95),
            ..Version == (int)KeyVersion.V6 ? Helper.Pack32(bytes.Length) : Helper.Pack16((short)bytes.Length),
            ..bytes
        ];
    }

    /// <summary>
    ///     Read public key from bytes
    /// </summary>
    public static PublicKey FromBytes(byte[] bytes)
    {
        var record = DecodePublicKey(bytes);
        return new PublicKey(
            record.Version,
            record.CreationTime,
            record.KeyAlgorithm,
            record.KeyMaterial
        );
    }

    protected static (int Version, DateTime CreationTime, KeyAlgorithm KeyAlgorithm, IKeyMaterial KeyMaterial)
        DecodePublicKey(byte[] bytes)
    {
        var offset = 0;

        // A one-octet version number.
        var version = bytes[offset++];

        // A four-octet number denoting the time that the key was created.
        var creationTime = DateTimeOffset.FromUnixTimeSeconds(
            BinaryPrimitives.ReadInt32BigEndian(
                bytes.Skip(offset).Take(4).ToArray()
            )
        ).LocalDateTime;
        offset += 4;

        // A one-octet number denoting the public-key algorithm of this key.
        var keyAlgorithm = (KeyAlgorithm)bytes[offset++];
        if (version == (int)KeyVersion.V6)
            // - A four-octet scalar octet count for the following key material.
            offset += 4;
        var keyMaterial = ReadKeyMaterial(
            bytes.Skip(offset).ToArray(), keyAlgorithm
        );
        return (version, creationTime, keyAlgorithm, keyMaterial);
    }

    private static IKeyMaterial ReadKeyMaterial(
        byte[] bytes, KeyAlgorithm keyAlgorithm
    )
    {
        return keyAlgorithm switch
        {
            KeyAlgorithm.RsaEncrypt or
                KeyAlgorithm.RsaGeneral or
                KeyAlgorithm.RsaSign => RsaPublicKeyMaterial.FromBytes(bytes),
            KeyAlgorithm.EcDh => EcDhPublicKeyMaterial.FromBytes(bytes),
            KeyAlgorithm.EcDsa => EcDsaPublicKeyMaterial.FromBytes(bytes),
            KeyAlgorithm.EdDsaLegacy => EdDsaLegacyPublicKeyMaterial.FromBytes(bytes),
            KeyAlgorithm.X25519 => MontgomeryPublicKeyMaterial.FromBytes(bytes, MontgomeryCurve.Curve25519),
            KeyAlgorithm.X448 => MontgomeryPublicKeyMaterial.FromBytes(bytes, MontgomeryCurve.Curve448),
            KeyAlgorithm.Ed25519 => EdDsaPublicKeyMaterial.FromBytes(bytes, EdDsaCurve.Ed25519),
            KeyAlgorithm.Ed448 => EdDsaPublicKeyMaterial.FromBytes(bytes, EdDsaCurve.Ed448),
            _ => throw new NotImplementedException($"Key material {keyAlgorithm} not implemented.")
        };
    }
}