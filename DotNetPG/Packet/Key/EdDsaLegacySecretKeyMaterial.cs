// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     EdDSALegacy secret key material class
/// </summary>
public class EdDsaLegacySecretKeyMaterial(BigInteger d, EdDsaLegacyPublicKeyMaterial publicMaterial)
    : EcSecretKeyMaterial(d, publicMaterial), ISignKeyMaterial
{
    public override bool IsValid()
    {
        var privateKey = new Ed25519PrivateKeyParameters(D.ToByteArrayUnsigned());
        var publicKey = privateKey.GeneratePublicKey();
        return publicMaterial.EncodedPoint.Equals(
            BigIntegers.FromUnsignedByteArray([0x40, ..publicKey.GetEncoded()])
        );
    }

    public byte[] Sign(HashAlgorithm hash, byte[] message)
    {
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);

        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(D.ToByteArrayUnsigned()));
        signer.BlockUpdate(digest, 0, digest.Length);
        var signature = signer.GenerateSignature();
        var size = Ed25519.SignatureSize / 2;
        return
        [
            ..Helper.Pack16((short)(size * 8)),
            ..signature.Take(size).ToArray(),
            ..Helper.Pack16((short)(size * 8)),
            ..signature.Skip(size).ToArray()
        ];
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EdDsaLegacySecretKeyMaterial FromBytes(byte[] bytes, EdDsaLegacyPublicKeyMaterial publicMaterial)
    {
        return new EdDsaLegacySecretKeyMaterial(Helper.ReadMpi(bytes), publicMaterial);
    }

    /// <summary>
    ///     Generate key material
    /// </summary>
    public static EdDsaLegacySecretKeyMaterial Generate()
    {
        var privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        var publicKey = privateKey.GeneratePublicKey();
        return new EdDsaLegacySecretKeyMaterial(
            BigIntegers.FromUnsignedByteArray(privateKey.GetEncoded()),
            new EdDsaLegacyPublicKeyMaterial(
                EcCurveOid(EcCurve.Ed25519),
                BigIntegers.FromUnsignedByteArray([0x40, ..publicKey.GetEncoded()])
            )
        );
    }
}