// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;

/// <summary>
///     Montgomery session key crypto
/// </summary>
public class MontgomerySessionKeyCrypto(byte[] ephemeralKey, byte[] wrappedKey) : ISessionKeyCrypto
{
    public byte[] EphemeralKey => ephemeralKey;

    public byte[] WrappedKey => wrappedKey;

    public byte[] Decrypt(ISecretKeyPacket secretKey)
    {
        if (secretKey.SecretKeyMaterial is not MontgomerySecretKeyMaterial km)
            throw new ArgumentException("Secret key material is not Montgomery key");
        var kek = Helper.Hkdf(
            [
                ..ephemeralKey,
                ..km.PublicKey,
                ..km.ComputeSecret(ephemeralKey)
            ],
            km.KekSize,
            km.HkdfHash,
            info: km.HkdfInfo
        );
        var wrapper = new AesWrapEngine();
        wrapper.Init(false, new KeyParameter(kek));
        return wrapper.Unwrap(wrappedKey, 0, wrappedKey.Length);
    }

    public byte[] ToBytes()
    {
        return [..ephemeralKey, (byte)wrappedKey.Length, ..wrappedKey];
    }

    public static MontgomerySessionKeyCrypto FromBytes(
        byte[] bytes, MontgomeryCurve curve
    )
    {
        var size = curve == MontgomeryCurve.Curve25519 ? X25519.ScalarSize : X448.ScalarSize;
        return new MontgomerySessionKeyCrypto(
            bytes.Take(size).ToArray(),
            bytes.Skip(size + 1).Take(bytes[size]).ToArray()
        );
    }

    /// <summary>
    ///     Produce crypto by encrypting session key
    /// </summary>
    public static MontgomerySessionKeyCrypto EncryptSessionKey(
        byte[] sessionKey, MontgomeryPublicKeyMaterial key
    )
    {
        var secretKey = MontgomerySecretKeyMaterial.Generate(key.Curve);
        var ephemeralKey = secretKey.PublicKey;
        var kek = Helper.Hkdf(
            [
                ..ephemeralKey,
                ..key.PublicKey,
                ..secretKey.ComputeSecret(key.PublicKey)
            ],
            key.KekSize,
            key.HkdfHash,
            info: key.HkdfInfo
        );
        var wrapper = new AesWrapEngine();
        wrapper.Init(true, new KeyParameter(kek));
        return new MontgomerySessionKeyCrypto(
            ephemeralKey,
            wrapper.Wrap(sessionKey, 0, sessionKey.Length)
        );
    }
}