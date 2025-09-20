// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Type;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

/// <summary>
///     RSA session key crypto class.
/// </summary>
public class RsaSessionKeyCrypto(BigInteger encrypted) : ISessionKeyCrypto
{
    public BigInteger Encrypted => encrypted;

    public byte[] ToBytes()
    {
        return
        [
            ..Helper.Pack16((short)encrypted.BitLength),
            ..encrypted.ToByteArrayUnsigned()
        ];
    }

    public byte[] Decrypt(ISecretKeyPacket secretKey)
    {
        if (secretKey.SecretKeyMaterial is not RsaSecretKeyMaterial km)
            throw new ArgumentException("Secret key material is not RSA key");
        //var engine = new RsaEngine();
        var engine = new Pkcs1Encoding(new RsaEngine());
        engine.Init(false, km.KeyParameters);
        var data = encrypted.ToByteArrayUnsigned();
        return engine.ProcessBlock(data, 0, data.Length);
    }

    /// <summary>
    ///     Read RSA encrypted session key from byte string
    /// </summary>
    public static RsaSessionKeyCrypto FromBytes(byte[] bytes)
    {
        return new RsaSessionKeyCrypto(Helper.ReadMpi(bytes));
    }

    /// <summary>
    ///     Produce crypto by encrypting session key
    /// </summary>
    public static RsaSessionKeyCrypto EncryptSessionKey(
        byte[] sessionKey, RsaPublicKeyMaterial key
    )
    {
        var engine = new Pkcs1Encoding(new RsaEngine());
        engine.Init(true, key.KeyParameters);
        return new RsaSessionKeyCrypto(
            BigIntegers.FromUnsignedByteArray(
                engine.ProcessBlock(sessionKey, 0, sessionKey.Length)
            )
        );
    }
}