// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     ECDSA secret key material
/// </summary>
public class EcDsaSecretKeyMaterial(BigInteger d, EcDsaPublicKeyMaterial publicMaterial)
    : EcSecretKeyMaterial(d, publicMaterial), ISignKeyMaterial
{
    public byte[] Sign(HashAlgorithm hash, byte[] message)
    {
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);
        var parameters = ECNamedDomainParameters.LookupOid(publicMaterial.CurveOid);
        var signer = new ECDsaSigner();
        signer.Init(true, new ECPrivateKeyParameters("ECDSA", D, parameters));
        var signature = signer.GenerateSignature(digest);
        var r = signature[0];
        var s = signature[1];
        return
        [
            ..Helper.Pack16((short)r.BitLength),
            ..r.ToByteArrayUnsigned(),
            ..Helper.Pack16((short)s.BitLength),
            ..s.ToByteArrayUnsigned()
        ];
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EcDsaSecretKeyMaterial FromBytes(byte[] bytes, EcDsaPublicKeyMaterial publicMaterial)
    {
        return new EcDsaSecretKeyMaterial(Helper.ReadMpi(bytes), publicMaterial);
    }

    /// <summary>
    ///     Generate key material
    /// </summary>
    public static EcDsaSecretKeyMaterial Generate(EcCurve curve)
    {
        switch (curve)
        {
            case EcCurve.Ed25519:
            case EcCurve.Curve25519:
                throw new ArgumentException("Ed25519 or Curve25519 curve is not supported for ECDSA key generation.");
            default:
                var keyPair = GenerateKeyPair(curve);
                var pubKey = (ECPublicKeyParameters)keyPair.Public;
                var priKey = (ECPrivateKeyParameters)keyPair.Private;
                return new EcDsaSecretKeyMaterial(
                    priKey.D,
                    new EcDsaPublicKeyMaterial(
                        EcCurveOid(curve),
                        BigIntegers.FromUnsignedByteArray(pubKey.Q.GetEncoded())
                    )
                );
        }
    }
}