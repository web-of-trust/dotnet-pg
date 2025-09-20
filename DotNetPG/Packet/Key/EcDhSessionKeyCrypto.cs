// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     ECDH session key crypto.
/// </summary>
public class EcDhSessionKeyCrypto(BigInteger ephemeralKey, byte[] wrappedKey) : ISessionKeyCrypto
{
    private const string AnonymousSender = "Anonymous Sender    ";
    private const int Pkcs5BlockSize = 8;

    public BigInteger EphemeralKey => ephemeralKey;

    public byte[] WrappedKey => wrappedKey;

    public byte[] ToBytes()
    {
        return
        [
            ..Helper.Pack16((short)ephemeralKey.BitLength),
            ..ephemeralKey.ToByteArrayUnsigned(),
            (byte)wrappedKey.Length,
            ..wrappedKey
        ];
    }

    public byte[] Decrypt(ISecretKeyPacket secretKey)
    {
        if (secretKey.SecretKeyMaterial is not EcDhSecretKeyMaterial km)
            throw new Exception("Key material is not ECDH key.");

        byte[] sharedSecret;
        switch (km.Curve)
        {
            case EcCurve.Curve25519:
                var privateKey = new X25519PrivateKeyParameters(km.D.ToByteArrayUnsigned().Reverse().ToArray());
                var agreement = new X25519Agreement();
                agreement.Init(privateKey);
                sharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(
                    new X25519PublicKeyParameters(
                        ephemeralKey.ToByteArrayUnsigned().Skip(1).ToArray()
                    ),
                    sharedSecret
                );
                break;
            case EcCurve.Ed25519:
                throw new Exception("Ed25519 curve is unsupported for key agreement calculation.");
            default:
                var parameters = ECNamedDomainParameters.LookupOid(km.CurveOid);
                var q = parameters.Curve.DecodePoint(ephemeralKey.ToByteArrayUnsigned());

                var ecdhAgreement = new ECDHBasicAgreement();
                ecdhAgreement.Init(new ECPrivateKeyParameters("ECDH", km.D, parameters));
                var secret = ecdhAgreement.CalculateAgreement(
                    new ECPublicKeyParameters("ECDH", q, parameters)
                );
                sharedSecret = BigIntegers.AsUnsignedByteArray(ecdhAgreement.GetFieldSize(), secret);
                break;
        }

        var publicKm = (EcDhPublicKeyMaterial)km.PublicMaterial;
        var keySize = (Helper.SymmetricKeySize(publicKm.KdfSymmetric) + 7) >> 3;
        var kek = EcDhKdf(publicKm.KdfHash, sharedSecret, EcDhParam(publicKm, secretKey.Fingerprint), keySize);

        var wrapper = SelectKeyWrapper(publicKm.KdfSymmetric);
        wrapper.Init(false, new KeyParameter(kek));
        return Pkcs5Decode(wrapper.Unwrap(wrappedKey, 0, wrappedKey.Length));
    }

    /// <summary>
    ///     Read encrypted session key from bytes
    /// </summary>
    public static EcDhSessionKeyCrypto FromBytes(byte[] bytes)
    {
        var ephemeralKey = Helper.ReadMpi(bytes);
        var offset = ((ephemeralKey.BitLength + 7) >> 3) + 2;
        var length = bytes[offset++];
        return new EcDhSessionKeyCrypto(
            ephemeralKey, bytes.Skip(offset).Take(length).ToArray()
        );
    }

    /// <summary>
    ///     Produce crypto by encrypting session key
    /// </summary>
    public static EcDhSessionKeyCrypto EncryptSessionKey(
        byte[] sessionKey, EcDhPublicKeyMaterial key, byte[] fingerprint
    )
    {
        BigInteger ephemeralKey;
        byte[] sharedSecret;
        switch (key.Curve)
        {
            case EcCurve.Curve25519:
                var privateKey = new X25519PrivateKeyParameters(new SecureRandom());
                var publicKey = privateKey.GeneratePublicKey();
                ephemeralKey = BigIntegers.FromUnsignedByteArray(
                    [0x40, ..publicKey.GetEncoded()]
                );

                var agreement = new X25519Agreement();
                agreement.Init(privateKey);
                sharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(
                    new X25519PublicKeyParameters(
                        key.EncodedPoint.ToByteArrayUnsigned().Skip(1).ToArray()
                    ),
                    sharedSecret
                );
                break;
            case EcCurve.Ed25519:
                throw new Exception("Ed25519 curve is unsupported for ephemeral key generation.");
            default:
                var generator = new ECKeyPairGenerator();
                generator.Init(
                    new ECKeyGenerationParameters(
                        ECDomainParameters.LookupName(key.Curve.ToString().ToLower()),
                        new SecureRandom()
                    )
                );
                var keyPair = generator.GenerateKeyPair();
                var pubKey = (ECPublicKeyParameters)keyPair.Public;
                ephemeralKey = BigIntegers.FromUnsignedByteArray(pubKey.Q.GetEncoded());

                var parameters = ECNamedDomainParameters.LookupOid(key.CurveOid);
                var q = parameters.Curve.DecodePoint(key.EncodedPoint.ToByteArrayUnsigned());

                var ecdhAgreement = new ECDHBasicAgreement();
                ecdhAgreement.Init(keyPair.Private);
                var secret = ecdhAgreement.CalculateAgreement(
                    new ECPublicKeyParameters("ECDH", q, parameters)
                );
                sharedSecret = BigIntegers.AsUnsignedByteArray(ecdhAgreement.GetFieldSize(), secret);
                break;
        }

        var keySize = (Helper.SymmetricKeySize(key.KdfSymmetric) + 7) >> 3;
        var kek = EcDhKdf(key.KdfHash, sharedSecret, EcDhParam(key, fingerprint), keySize);

        var wrapper = SelectKeyWrapper(key.KdfSymmetric);
        wrapper.Init(true, new KeyParameter(kek));
        var pkcs5Sk = Pkcs5Encode(sessionKey);
        return new EcDhSessionKeyCrypto(
            ephemeralKey, wrapper.Wrap(pkcs5Sk, 0, pkcs5Sk.Length)
        );
    }

    public static byte[] EcDhKdf(
        HashAlgorithm hash, byte[] sharedSecret, byte[] param, int keySize
    )
    {
        return DigestUtilities.CalculateDigest(hash.ToString(), [
            0, 0, 0, 1,
            ..sharedSecret,
            ..param
        ]).Take(keySize).ToArray();
    }

    private static byte[] EcDhParam(EcDhPublicKeyMaterial key, byte[] fingerprint)
    {
        return
        [
            ..key.CurveOid.GetEncoded().Skip(1).ToArray(),
            (byte)KeyAlgorithm.EcDh,
            0x03,
            (byte)key.Reserved,
            (byte)key.KdfHash,
            (byte)key.KdfSymmetric,
            ..Encoding.UTF8.GetBytes(AnonymousSender),
            ..fingerprint
        ];
    }

    private static byte[] Pkcs5Encode(byte[] message)
    {
        var c = Pkcs5BlockSize - message.Length % Pkcs5BlockSize;
        var result = new byte[message.Length + c];
        Array.Fill(result, (byte)c);
        Array.Copy(message, 0, result, 0, message.Length);
        return result;
    }

    private static byte[] Pkcs5Decode(byte[] message)
    {
        var length = message.Length;
        if (length > 0)
        {
            var c = message[length - 1];
            if (c >= 1)
            {
                var provided = message.Skip(length - c).ToArray();
                var computed = new byte[c];
                Array.Fill(computed, c);
                if (Arrays.AreEqual(provided, computed)) return message.Take(length - c).ToArray();
            }
        }

        return [];
    }

    private static IWrapper SelectKeyWrapper(SymmetricAlgorithm symmetric)
    {
        return symmetric switch
        {
            SymmetricAlgorithm.Camellia128 or
                SymmetricAlgorithm.Camellia192 or
                SymmetricAlgorithm.Camellia256 => new CamelliaWrapEngine(),
            _ => new AesWrapEngine()
        };
    }
}