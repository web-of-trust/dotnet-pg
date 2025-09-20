// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Enum;
using Type;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     EdDSA secret key material class
/// </summary>
public class EdDsaSecretKeyMaterial(byte[] secretKey, EdDsaPublicKeyMaterial publicMaterial) : ISignKeyMaterial
{
    public byte[] SecretKey => secretKey;

    public IKeyMaterial PublicMaterial => publicMaterial;

    public int KeyLength => publicMaterial.KeyLength;

    public bool IsValid()
    {
        switch (publicMaterial.Curve)
        {
            case EdDsaCurve.Ed448:
                var pk448 = new Ed448PrivateKeyParameters(secretKey).GeneratePublicKey();
                return Arrays.AreEqual(pk448.GetEncoded(), publicMaterial.PublicKey);
            case EdDsaCurve.Ed25519:
            default:
                var pk255 = new Ed25519PrivateKeyParameters(secretKey).GeneratePublicKey();
                return Arrays.AreEqual(pk255.GetEncoded(), publicMaterial.PublicKey);
        }
    }

    public byte[] ToBytes()
    {
        return secretKey;
    }

    public byte[] Sign(HashAlgorithm hash, byte[] message)
    {
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);
        ISigner signer = publicMaterial.Curve switch
        {
            EdDsaCurve.Ed448 => new Ed448Signer([]),
            _ => new Ed25519Signer()
        };
        ICipherParameters parameter = publicMaterial.Curve switch
        {
            EdDsaCurve.Ed448 => new Ed448PrivateKeyParameters(secretKey),
            _ => new Ed25519PrivateKeyParameters(secretKey)
        };
        signer.Init(true, parameter);
        signer.BlockUpdate(digest, 0, digest.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EdDsaSecretKeyMaterial FromBytes(byte[] bytes, EdDsaPublicKeyMaterial publicMaterial)
    {
        var size = publicMaterial.Curve == EdDsaCurve.Ed25519 ? Ed25519.SecretKeySize : Ed448.SecretKeySize;
        return new EdDsaSecretKeyMaterial(bytes.Take(size).ToArray(), publicMaterial);
    }

    /// <summary>
    ///     Generate key material
    /// </summary>
    public static EdDsaSecretKeyMaterial Generate(EdDsaCurve curve)
    {
        switch (curve)
        {
            case EdDsaCurve.Ed448:
                var pk448 = new Ed448PrivateKeyParameters(new SecureRandom());
                return new EdDsaSecretKeyMaterial(
                    pk448.GetEncoded(),
                    new EdDsaPublicKeyMaterial(pk448.GeneratePublicKey().GetEncoded(), curve)
                );
            case EdDsaCurve.Ed25519:
            default:
                var pk255 = new Ed25519PrivateKeyParameters(new SecureRandom());
                return new EdDsaSecretKeyMaterial(
                    pk255.GetEncoded(),
                    new EdDsaPublicKeyMaterial(pk255.GeneratePublicKey().GetEncoded(), curve)
                );
        }
    }
}