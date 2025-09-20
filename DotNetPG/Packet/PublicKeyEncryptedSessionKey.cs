// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Key;
using Type;

/// <summary>
///     Implementation Public-Key Encrypted Session Key (PKESK) packet (Tag 1).
/// </summary>
public class PublicKeyEncryptedSessionKey : BasePacket, IPublicKeyEncryptedSessionKey
{
    private const int Version3 = 3;
    private const int Version6 = 6;

    public PublicKeyEncryptedSessionKey(
        int version,
        int keyVersion,
        byte[] keyFingerprint,
        byte[] keyId,
        KeyAlgorithm keyAlgorithm,
        ISessionKeyCrypto sessionKeyCrypto,
        ISessionKey? sessionKey = null
    ) : base(PacketType.PublicKeyEncryptedSessionKey)
    {
        Version = version;
        KeyVersion = keyVersion;
        KeyFingerprint = keyFingerprint;
        KeyId = keyId;
        KeyAlgorithm = keyAlgorithm;
        SessionKeyCrypto = sessionKeyCrypto;
        SessionKey = sessionKey;

        if (version != Version3 && version != Version6)
            throw new ArgumentException(
                $"Version {version} of the PKESK packet is unsupported."
            );
        Helper.AssertKeyAlgorithm(keyAlgorithm);
    }

    public int Version { get; }

    public int KeyVersion { get; }

    public byte[] KeyFingerprint { get; }

    public byte[] KeyId { get; }

    public KeyAlgorithm KeyAlgorithm { get; }

    public ISessionKeyCrypto SessionKeyCrypto { get; }

    public ISessionKey? SessionKey { get; }

    public IEncryptedSessionKey Decrypt(ISecretKeyPacket secretKey)
    {
        if (SessionKey != null) return this;
        return new PublicKeyEncryptedSessionKey(
            Version,
            secretKey.Version,
            secretKey.Fingerprint,
            secretKey.KeyId,
            secretKey.KeyAlgorithm,
            SessionKeyCrypto,
            DecryptSessionKey(secretKey)
        );
    }

    /// <summary>
    ///     Read PKESK packet from bytes
    /// </summary>
    public static PublicKeyEncryptedSessionKey FromBytes(byte[] bytes)
    {
        var offset = 0;
        var version = bytes[offset++];
        int keyVersion;
        byte[] keyFingerprint;
        byte[] keyId;
        if (version == Version6)
        {
            var length = bytes[offset++];
            keyVersion = bytes[offset++];
            keyFingerprint = bytes.Skip(offset).Take(length - 1).ToArray();
            offset += length - 1;
            keyId = keyVersion == (int)Enum.KeyVersion.V6
                ? keyFingerprint.Take(PublicKey.KeyIdSize).ToArray()
                : keyFingerprint.Skip(12).Take(PublicKey.KeyIdSize).ToArray();
        }
        else
        {
            keyId = bytes.Skip(offset).Take(PublicKey.KeyIdSize).ToArray();
            offset += PublicKey.KeyIdSize;
            keyVersion = 0;
            keyFingerprint = [];
        }

        var keyAlgorithm = (KeyAlgorithm)bytes[offset++];

        return new PublicKeyEncryptedSessionKey(
            version,
            keyVersion,
            keyFingerprint,
            keyId,
            keyAlgorithm,
            ReadMaterial(bytes.Skip(offset).ToArray(), keyAlgorithm)
        );
    }

    /// <summary>
    ///     Encrypt session key
    /// </summary>
    public static PublicKeyEncryptedSessionKey EncryptSessionKey(
        ISessionKey sessionKey, IKeyPacket keyPacket
    )
    {
        var version = keyPacket.IsV6Key ? Version6 : Version3;
        return new PublicKeyEncryptedSessionKey(
            version,
            keyPacket.Version,
            keyPacket.Fingerprint,
            keyPacket.KeyId,
            keyPacket.KeyAlgorithm,
            ProduceSessionKeyCrypto(sessionKey, keyPacket, version),
            sessionKey
        );
    }

    public override byte[] ToBytes()
    {
        return
        [
            (byte)Version,
            ..Version == Version6 ? [(byte)(KeyFingerprint.Length + 1)] : Array.Empty<byte>(),
            ..Version == Version6 ? [(byte)KeyVersion] : Array.Empty<byte>(),
            ..Version == Version6 ? KeyFingerprint : [],
            ..Version == Version3 ? KeyId : [],
            (byte)KeyAlgorithm,
            ..SessionKeyCrypto.ToBytes()
        ];
    }

    private ISessionKey DecryptSessionKey(ISecretKeyPacket secretKey)
    {
        var keyData = SessionKeyCrypto.Decrypt(secretKey);
        switch (secretKey.KeyAlgorithm)
        {
            case KeyAlgorithm.RsaGeneral:
            case KeyAlgorithm.RsaEncrypt:
            case KeyAlgorithm.EcDh:
                if (Version == Version3) return Key.SessionKey.FromBytes(keyData);
                var keyLength = keyData.Length - 2;
                var sessionKey = new SessionKey(keyData.Take(keyLength).ToArray());
                return sessionKey.Checksum(keyData.Skip(keyLength).ToArray());
            case KeyAlgorithm.X25519:
            case KeyAlgorithm.X448:
                return new SessionKey(keyData);
            default:
                throw new Exception(
                    $"{secretKey.KeyAlgorithm} key algorithm is unsupported."
                );
        }
    }

    private static ISessionKeyCrypto ProduceSessionKeyCrypto(
        ISessionKey sessionKey, IKeyPacket keyPacket, int version
    )
    {
        return keyPacket.KeyMaterial switch
        {
            RsaPublicKeyMaterial rsa => RsaSessionKeyCrypto.EncryptSessionKey(
                version == Version3
                    ? [..sessionKey.ToBytes(), ..sessionKey.ComputeChecksum()]
                    : [..sessionKey.EncryptionKey, ..sessionKey.ComputeChecksum()],
                rsa
            ),
            EcDhPublicKeyMaterial ecdh => EcDhSessionKeyCrypto.EncryptSessionKey(
                version == Version3
                    ? [..sessionKey.ToBytes(), ..sessionKey.ComputeChecksum()]
                    : [..sessionKey.EncryptionKey, ..sessionKey.ComputeChecksum()],
                ecdh, keyPacket.Fingerprint
            ),
            MontgomeryPublicKeyMaterial montgomery => MontgomerySessionKeyCrypto.EncryptSessionKey(
                sessionKey.EncryptionKey, montgomery
            ),
            _ => throw new Exception($"{keyPacket.KeyAlgorithm} key algorithm is unsupported.")
        };
    }

    private static ISessionKeyCrypto ReadMaterial(byte[] bytes, KeyAlgorithm keyAlgorithm)
    {
        return keyAlgorithm switch
        {
            KeyAlgorithm.EcDh => EcDhSessionKeyCrypto.FromBytes(bytes),
            KeyAlgorithm.RsaGeneral or KeyAlgorithm.RsaEncrypt => RsaSessionKeyCrypto.FromBytes(bytes),
            KeyAlgorithm.X25519 => MontgomerySessionKeyCrypto.FromBytes(bytes, MontgomeryCurve.Curve25519),
            KeyAlgorithm.X448 => MontgomerySessionKeyCrypto.FromBytes(bytes, MontgomeryCurve.Curve448),
            _ => throw new NotImplementedException($"{keyAlgorithm} key algorithm is unsupported.")
        };
    }
}