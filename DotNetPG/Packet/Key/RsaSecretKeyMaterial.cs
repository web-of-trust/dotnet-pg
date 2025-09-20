// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     RSA secret key material class
/// </summary>
public class RsaSecretKeyMaterial(
    BigInteger exponent,
    BigInteger primeP,
    BigInteger primeQ,
    BigInteger coefficient,
    RsaPublicKeyMaterial publicMaterial)
    : ISignKeyMaterial
{
    public BigInteger Exponent => exponent;
    public BigInteger PrimeP => primeP;
    public BigInteger PrimeQ => primeQ;
    public BigInteger Coefficient => coefficient;

    public AsymmetricKeyParameter KeyParameters => new RsaPrivateCrtKeyParameters(
        publicMaterial.Modulus,
        publicMaterial.Exponent,
        exponent,
        primeP,
        primeQ,
        exponent.Remainder(primeP.Subtract(BigInteger.One)),
        exponent.Remainder(primeQ.Subtract(BigInteger.One)),
        BigIntegers.ModOddInverse(primeP, primeQ)
    );

    public IKeyMaterial PublicMaterial => publicMaterial;

    public int KeyLength => publicMaterial.KeyLength;

    public bool IsValid()
    {
        // expect pq = n
        if (primeP.Multiply(primeQ).CompareTo(publicMaterial.Modulus) != 0) return false;

        // expect p*u = 1 mod q
        if (primeP.Multiply(coefficient).Mod(primeQ).CompareTo(BigInteger.One) != 0) return false;

        var sizeOver3 = publicMaterial.Modulus.BitLength / 3;
        var r = Helper.RandomBigInteger(BigInteger.One, BigInteger.Two.ShiftLeft(sizeOver3));
        var rde = r.Multiply(exponent).Multiply(publicMaterial.Exponent);
        return rde.Mod(primeP.Subtract(BigInteger.One)).CompareTo(r) == 0 &&
               rde.Mod(primeQ.Subtract(BigInteger.One)).CompareTo(r) == 0;
    }

    public byte[] ToBytes()
    {
        return
        [
            ..Helper.Pack16((short)exponent.BitLength),
            ..exponent.ToByteArrayUnsigned(),
            ..Helper.Pack16((short)primeP.BitLength),
            ..primeP.ToByteArrayUnsigned(),
            ..Helper.Pack16((short)primeQ.BitLength),
            ..primeQ.ToByteArrayUnsigned(),
            ..Helper.Pack16((short)coefficient.BitLength),
            ..coefficient.ToByteArrayUnsigned()
        ];
    }

    public byte[] Sign(HashAlgorithm hash, byte[] message)
    {
        var signer = new RsaDigestSigner(Helper.HashDigest(hash));
        signer.Init(true, KeyParameters);
        signer.BlockUpdate(message, 0, message.Length);
        var signature = signer.GenerateSignature();
        return [..Helper.Pack16((short)(signature.Length * 8)), ..signature];
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static RsaSecretKeyMaterial FromBytes(byte[] bytes, RsaPublicKeyMaterial publicMaterial)
    {
        var exponent = Helper.ReadMpi(bytes);

        var offset = ((exponent.BitLength + 7) >> 3) + 2;
        var primeP = Helper.ReadMpi(bytes.Skip(offset).ToArray());

        offset += ((primeP.BitLength + 7) >> 3) + 2;
        var primeQ = Helper.ReadMpi(bytes.Skip(offset).ToArray());

        offset += ((primeQ.BitLength + 7) >> 3) + 2;
        var coefficient = Helper.ReadMpi(bytes.Skip(offset).ToArray());

        return new RsaSecretKeyMaterial(
            exponent, primeP, primeQ, coefficient, publicMaterial
        );
    }

    public static RsaSecretKeyMaterial Generate(RsaKeySize keySize = RsaKeySize.Normal)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), (int)keySize));
        var keyPair = generator.GenerateKeyPair();
        var pubKey = (RsaKeyParameters)keyPair.Public;
        var priKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
        return new RsaSecretKeyMaterial(
            priKey.Exponent,
            priKey.P,
            priKey.Q,
            priKey.P.ModInverse(priKey.Q),
            new RsaPublicKeyMaterial(pubKey.Modulus, pubKey.Exponent)
        );
    }
}