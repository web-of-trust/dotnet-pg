// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Enum;
using Type;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Montgomery secret key material
/// </summary>
public class MontgomerySecretKeyMaterial(byte[] secretKey, MontgomeryPublicKeyMaterial publicMaterial)
    : IKeyMaterial
{
    public byte[] SecretKey => secretKey;

    public byte[] PublicKey => publicMaterial.PublicKey;

    public int KekSize => publicMaterial.KekSize;

    public HashAlgorithm HkdfHash => publicMaterial.HkdfHash;

    public byte[] HkdfInfo => publicMaterial.HkdfInfo;

    public AsymmetricKeyParameter KeyParameters => publicMaterial.Curve == MontgomeryCurve.Curve448
        ? new X448PrivateKeyParameters(secretKey)
        : new X25519PrivateKeyParameters(secretKey);

    public IKeyMaterial PublicMaterial => publicMaterial;

    public int KeyLength => publicMaterial.KeyLength;

    public bool IsValid()
    {
        switch (publicMaterial.Curve)
        {
            case MontgomeryCurve.Curve448:
                var public448 = new X448PrivateKeyParameters(secretKey).GeneratePublicKey();
                return Arrays.AreEqual(public448.GetEncoded(), publicMaterial.PublicKey);
            default:
                var public255 = new X25519PrivateKeyParameters(secretKey).GeneratePublicKey();
                return Arrays.AreEqual(public255.GetEncoded(), publicMaterial.PublicKey);
        }
    }

    public byte[] ToBytes()
    {
        return secretKey;
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static MontgomerySecretKeyMaterial FromBytes(byte[] bytes, MontgomeryPublicKeyMaterial publicMaterial)
    {
        var size = publicMaterial.Curve == MontgomeryCurve.Curve25519 ? X25519.ScalarSize : X448.ScalarSize;
        return new MontgomerySecretKeyMaterial(bytes.Take(size).ToArray(), publicMaterial);
    }

    /// <summary>
    ///     Generate key material
    /// </summary>
    public static MontgomerySecretKeyMaterial Generate(MontgomeryCurve curve)
    {
        switch (curve)
        {
            case MontgomeryCurve.Curve448:
                var private448 = new X448PrivateKeyParameters(new SecureRandom());
                var public448 = private448.GeneratePublicKey();
                return new MontgomerySecretKeyMaterial(
                    private448.GetEncoded(),
                    new MontgomeryPublicKeyMaterial(public448.GetEncoded(), curve)
                );
            default:
                var private255 = new X25519PrivateKeyParameters(new SecureRandom());
                var public255 = private255.GeneratePublicKey();
                return new MontgomerySecretKeyMaterial(
                    private255.GetEncoded(),
                    new MontgomeryPublicKeyMaterial(public255.GetEncoded(), curve)
                );
        }
    }

    public byte[] ComputeSecret(byte[] publicKey)
    {
        byte[] secret;
        switch (publicMaterial.Curve)
        {
            case MontgomeryCurve.Curve448:
                var x448Agreement = new X448Agreement();
                x448Agreement.Init(new X448PrivateKeyParameters(secretKey));
                secret = new byte[x448Agreement.AgreementSize];
                x448Agreement.CalculateAgreement(new X448PublicKeyParameters(publicKey), secret);
                break;
            default:
                var x255Agreement = new X25519Agreement();
                x255Agreement.Init(new X25519PrivateKeyParameters(secretKey));
                secret = new byte[x255Agreement.AgreementSize];
                x255Agreement.CalculateAgreement(new X25519PublicKeyParameters(publicKey), secret);
                break;
        }

        return secret;
    }
}