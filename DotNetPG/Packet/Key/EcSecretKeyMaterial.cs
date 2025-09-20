// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

/// <summary>
///     EC secret key material class
/// </summary>
public abstract class EcSecretKeyMaterial(BigInteger d, EcPublicKeyMaterial publicMaterial) : IEcKeyMaterial
{
    public BigInteger D => d;

    public DerObjectIdentifier CurveOid => publicMaterial.CurveOid;

    public BigInteger EncodedPoint => publicMaterial.EncodedPoint;
    public IKeyMaterial PublicMaterial => publicMaterial;

    public int KeyLength => publicMaterial.KeyLength;

    public EcCurve Curve => publicMaterial.Curve;

    public virtual bool IsValid()
    {
        switch (publicMaterial.Curve)
        {
            case EcCurve.Ed25519:
            case EcCurve.Curve25519:
                return false;
            default:
                var parameters = ECNamedDomainParameters.LookupOid(publicMaterial.CurveOid);
                var q = parameters.Curve.DecodePoint(publicMaterial.EncodedPoint.ToByteArrayUnsigned());
                return q is { IsInfinity: false } && parameters.G.Multiply(d).Equals(q);
        }
    }

    public byte[] ToBytes()
    {
        return
        [
            ..Helper.Pack16((short)d.BitLength),
            ..d.ToByteArrayUnsigned()
        ];
    }

    protected static DerObjectIdentifier EcCurveOid(EcCurve curve)
    {
        var id = curve switch
        {
            EcCurve.Ed25519 => "1.3.6.1.4.1.11591.15.1",
            EcCurve.Curve25519 => "1.3.6.1.4.1.3029.1.5.1",
            EcCurve.Secp256R1 => "1.2.840.10045.3.1.7",
            EcCurve.Secp384R1 => "1.3.132.0.34",
            EcCurve.Secp521R1 => "1.3.132.0.35",
            EcCurve.BrainpoolP256R1 => "1.3.36.3.3.2.8.1.1.7",
            EcCurve.BrainpoolP384R1 => "1.3.36.3.3.2.8.1.1.11",
            EcCurve.BrainpoolP512R1 => "1.3.36.3.3.2.8.1.1.13",
            _ => throw new ArgumentException("Invalid curve")
        };
        DerObjectIdentifier.TryFromID(id, out var oid);
        return oid;
    }

    protected static AsymmetricCipherKeyPair GenerateKeyPair(EcCurve curve)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(
            new ECKeyGenerationParameters(
                ECDomainParameters.LookupName(curve.ToString().ToLower()),
                new SecureRandom()
            )
        );
        return generator.GenerateKeyPair();
    }
}