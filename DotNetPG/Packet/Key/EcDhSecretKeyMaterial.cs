// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     ECDH secret key material class
/// </summary>
public class EcDhSecretKeyMaterial(BigInteger d, EcDhPublicKeyMaterial publicMaterial)
    : EcSecretKeyMaterial(d, publicMaterial)
{
    /// <summary>
    ///     key material from bytes
    /// </summary>
    public static EcDhSecretKeyMaterial FromBytes(byte[] bytes, EcDhPublicKeyMaterial publicMaterial)
    {
        return new EcDhSecretKeyMaterial(Helper.ReadMpi(bytes), publicMaterial);
    }

    /// <summary>
    ///     Generate key material
    /// </summary>
    public static EcDhSecretKeyMaterial Generate(EcCurve curve)
    {
        switch (curve)
        {
            case EcCurve.Curve25519:
                var privateKey = new X25519PrivateKeyParameters(new SecureRandom());
                var publicKey = privateKey.GeneratePublicKey();
                var secret = privateKey.GetEncoded();
                return new EcDhSecretKeyMaterial(
                    BigIntegers.FromUnsignedByteArray(secret.Reverse().ToArray()),
                    new EcDhPublicKeyMaterial(
                        EcCurveOid(curve),
                        BigIntegers.FromUnsignedByteArray([0x40, ..publicKey.GetEncoded()]),
                        CurveHash(curve),
                        CurveSymmetric(curve)
                    )
                );
            case EcCurve.Ed25519:
                throw new ArgumentException("Ed25519 curve is unsupported for ECDH key generation.");
            default:
                var keyPair = GenerateKeyPair(curve);
                var pubKey = (ECPublicKeyParameters)keyPair.Public;
                var priKey = (ECPrivateKeyParameters)keyPair.Private;
                return new EcDhSecretKeyMaterial(
                    priKey.D,
                    new EcDhPublicKeyMaterial(
                        EcCurveOid(curve),
                        BigIntegers.FromUnsignedByteArray(pubKey.Q.GetEncoded()),
                        CurveHash(curve),
                        CurveSymmetric(curve)
                    )
                );
        }
    }

    public override bool IsValid()
    {
        if (publicMaterial.Curve == EcCurve.Curve25519)
        {
            var privateKey = new X25519PrivateKeyParameters(D.ToByteArrayUnsigned().Reverse().ToArray());
            var publicKey = privateKey.GeneratePublicKey();
            return publicMaterial.EncodedPoint.Equals(
                BigIntegers.FromUnsignedByteArray([0x40, ..publicKey.GetEncoded()])
            );
        }

        return base.IsValid();
    }

    private static HashAlgorithm CurveHash(EcCurve curve)
    {
        return curve switch
        {
            EcCurve.Secp256R1 or EcCurve.BrainpoolP256R1 or EcCurve.Curve25519 => HashAlgorithm.Sha256,
            EcCurve.Secp384R1 or EcCurve.BrainpoolP384R1 => HashAlgorithm.Sha384,
            EcCurve.Secp521R1 or EcCurve.BrainpoolP512R1 or EcCurve.Ed25519 => HashAlgorithm.Sha512,
            _ => HashAlgorithm.Sha256
        };
    }

    private static SymmetricAlgorithm CurveSymmetric(EcCurve curve)
    {
        return curve switch
        {
            EcCurve.Secp256R1 or EcCurve.BrainpoolP256R1 or EcCurve.Curve25519 or EcCurve.Ed25519 => SymmetricAlgorithm
                .Aes128,
            EcCurve.Secp384R1 or EcCurve.BrainpoolP384R1 => SymmetricAlgorithm.Aes192,
            _ => SymmetricAlgorithm.Aes256
        };
    }
}