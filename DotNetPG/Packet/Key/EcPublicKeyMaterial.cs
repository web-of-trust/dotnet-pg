// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

/// <summary>
///     EC public key material class
/// </summary>
public abstract class EcPublicKeyMaterial : IEcKeyMaterial
{
    protected EcPublicKeyMaterial(DerObjectIdentifier oid, BigInteger point)
    {
        CurveOid = oid;
        EncodedPoint = point;
        Curve = CurveFromOid(CurveOid);
        switch (Curve)
        {
            case EcCurve.Ed25519:
            case EcCurve.Curve25519:
                KeyLength = 255;
                break;
            default:
                var parameters = ECNamedDomainParameters.LookupOid(CurveOid);
                KeyLength = parameters.Curve.FieldSize;
                break;
        }
    }

    public DerObjectIdentifier CurveOid { get; }

    public BigInteger EncodedPoint { get; }

    public IKeyMaterial PublicMaterial => this;

    public int KeyLength { get; }

    public EcCurve Curve { get; }

    public bool IsValid()
    {
        return true;
    }

    public virtual byte[] ToBytes()
    {
        return
        [
            ..CurveOid.GetEncoded().Skip(1),
            ..Helper.Pack16((short)EncodedPoint.BitLength),
            ..EncodedPoint.ToByteArrayUnsigned()
        ];
    }

    private static EcCurve CurveFromOid(DerObjectIdentifier oid)
    {
        return oid.Id switch
        {
            "1.3.6.1.4.1.11591.15.1" => EcCurve.Ed25519,
            "1.3.6.1.4.1.3029.1.5.1" => EcCurve.Curve25519,
            "1.2.840.10045.3.1.7" => EcCurve.Secp256R1,
            "1.3.132.0.34" => EcCurve.Secp384R1,
            "1.3.132.0.35" => EcCurve.Secp521R1,
            "1.3.36.3.3.2.8.1.1.7" => EcCurve.BrainpoolP256R1,
            "1.3.36.3.3.2.8.1.1.11" => EcCurve.BrainpoolP384R1,
            "1.3.36.3.3.2.8.1.1.13" => EcCurve.BrainpoolP512R1,
            _ => throw new ArgumentException("Invalid OID")
        };
    }
}