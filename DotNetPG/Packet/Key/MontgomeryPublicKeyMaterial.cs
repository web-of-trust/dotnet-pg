// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Enum;
using Type;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;

/// <summary>
///     Montgomery public key material class
/// </summary>
public class MontgomeryPublicKeyMaterial(byte[] publicKey, MontgomeryCurve curve) : IKeyMaterial
{
    public byte[] PublicKey => publicKey;

    public MontgomeryCurve Curve => curve;

    public int KekSize => curve == MontgomeryCurve.Curve25519 ? 16 : 32;

    public HashAlgorithm HkdfHash => curve == MontgomeryCurve.Curve25519 ? HashAlgorithm.Sha256 : HashAlgorithm.Sha512;

    public byte[] HkdfInfo =>
        curve == MontgomeryCurve.Curve25519 ? "OpenPGP X25519"u8.ToArray() : "OpenPGP X448"u8.ToArray();

    public AsymmetricKeyParameter KeyParameters => curve == MontgomeryCurve.Curve448
        ? new X448PublicKeyParameters(publicKey)
        : new X25519PublicKeyParameters(publicKey);

    public IKeyMaterial PublicMaterial => this;

    public int KeyLength => curve == MontgomeryCurve.Curve25519 ? 255 : 448;

    public bool IsValid()
    {
        return true;
    }

    public byte[] ToBytes()
    {
        return publicKey;
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static MontgomeryPublicKeyMaterial FromBytes(byte[] bytes, MontgomeryCurve curve)
    {
        var size = curve == MontgomeryCurve.Curve25519 ? X25519.ScalarSize : X448.ScalarSize;
        return new MontgomeryPublicKeyMaterial(bytes.Take(size).ToArray(), curve);
    }
}