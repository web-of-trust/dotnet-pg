// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

/// <summary>
///     RSA public key material class
/// </summary>
public class RsaPublicKeyMaterial(BigInteger modulus, BigInteger exponent) : IVerifyKeyMaterial
{
    public BigInteger Modulus => modulus;

    public BigInteger Exponent => exponent;

    public AsymmetricKeyParameter KeyParameters => new RsaKeyParameters(false, modulus, exponent);

    public IKeyMaterial PublicMaterial => this;

    public int KeyLength => modulus.BitLength;

    public bool IsValid()
    {
        return true;
    }

    public byte[] ToBytes()
    {
        return
        [
            ..Helper.Pack16((short)modulus.BitLength),
            ..modulus.ToByteArrayUnsigned(),
            ..Helper.Pack16((short)exponent.BitLength),
            ..exponent.ToByteArrayUnsigned()
        ];
    }

    public bool Verify(HashAlgorithm hash, byte[] message, byte[] signature)
    {
        var verifier = new RsaDigestSigner(Helper.HashDigest(hash));
        verifier.Init(false, KeyParameters);
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(Helper.ReadMpi(signature).ToByteArrayUnsigned());
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static RsaPublicKeyMaterial FromBytes(byte[] bytes)
    {
        var modulus = Helper.ReadMpi(bytes);
        var modulusLength = (modulus.BitLength + 7) >> 3;
        return new RsaPublicKeyMaterial(
            modulus,
            Helper.ReadMpi(bytes.Skip(modulusLength + 2).ToArray())
        );
    }
}