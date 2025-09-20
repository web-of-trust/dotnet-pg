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

/// <summary>
///     EdDSA public key material
/// </summary>
public class EdDsaPublicKeyMaterial(byte[] publicKey, EdDsaCurve curve) : IVerifyKeyMaterial
{
    public byte[] PublicKey => publicKey;

    public EdDsaCurve Curve => curve;

    public IKeyMaterial PublicMaterial => this;

    public int KeyLength => Curve == EdDsaCurve.Ed25519 ? 255 : 448;

    public bool IsValid()
    {
        return true;
    }

    public byte[] ToBytes()
    {
        return publicKey;
    }

    public bool Verify(HashAlgorithm hash, byte[] message, byte[] signature)
    {
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);
        ISigner verifier = Curve switch
        {
            EdDsaCurve.Ed448 => new Ed448Signer([]),
            _ => new Ed25519Signer()
        };
        ICipherParameters parameter = Curve switch
        {
            EdDsaCurve.Ed448 => new Ed448PublicKeyParameters(publicKey),
            _ => new Ed25519PublicKeyParameters(publicKey)
        };
        verifier.Init(false, parameter);
        verifier.BlockUpdate(digest, 0, digest.Length);
        return verifier.VerifySignature(signature);
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EdDsaPublicKeyMaterial FromBytes(byte[] bytes, EdDsaCurve curve)
    {
        var size = curve == EdDsaCurve.Ed25519 ? Ed25519.PublicKeySize : Ed448.PublicKeySize;
        return new EdDsaPublicKeyMaterial(bytes.Take(size).ToArray(), curve);
    }
}