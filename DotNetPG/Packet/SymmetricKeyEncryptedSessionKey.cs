// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Crypto;
using Enum;
using Key;
using Type;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

/// <summary>
///     Implementation of the Symmetric Key Encrypted Session Key packet (Tag 3)
/// </summary>
public class SymmetricKeyEncryptedSessionKey : BasePacket, ISymmetricKeyEncryptedSessionKey
{
    private const int Version4 = 4;
    private const int Version5 = 5;
    private const int Version6 = 6;

    public SymmetricKeyEncryptedSessionKey(
        int version,
        IString2Key s2k,
        SymmetricAlgorithm symmetric,
        byte[] iv,
        byte[] encrypted,
        AeadAlgorithm? aead = null,
        ISessionKey? sessionKey = null
    ) : base(PacketType.SymmetricKeyEncryptedSessionKey)
    {
        Version = version;
        S2k = s2k;
        Symmetric = symmetric;
        Iv = iv;
        Encrypted = encrypted;
        Aead = aead;
        SessionKey = sessionKey;

        if (version != Version4 && version != Version5 && version != Version6)
            throw new ArgumentException(
                $"Version {version} of the SKESK packet is unsupported."
            );
        Helper.AssertSymmetric(symmetric);
        if (aead != null && version < Version5)
            throw new ArgumentException(
                $"Using AEAD with v{version} SKESK packet is not allowed."
            );
    }

    public int Version { get; }

    public IString2Key S2k { get; }

    public SymmetricAlgorithm Symmetric { get; }

    public AeadAlgorithm? Aead { get; }

    public byte[] Iv { get; }

    public byte[] Encrypted { get; }

    public ISessionKey? SessionKey { get; }

    public IEncryptedSessionKey Decrypt(string password)
    {
        if (SessionKey != null) return this;

        ISessionKey sessionKey;
        var keySize = (Helper.SymmetricKeySize(Symmetric) + 7) >> 3;
        var key = S2k.ProduceKey(
            password, keySize
        );
        if (Encrypted.Length == 0)
        {
            sessionKey = new SessionKey(key, Symmetric);
        }
        else
        {
            if (Aead != null)
            {
                byte[] adata =
                [
                    TypeByte,
                    (byte)Version,
                    (byte)Symmetric,
                    (byte)Aead
                ];
                var kek = Version == Version6 ? Helper.Hkdf(key, keySize, info: adata) : key;
                var aeadCipher = new AeadCipher(
                    kek, (AeadAlgorithm)Aead, Symmetric
                );
                sessionKey = new SessionKey(
                    aeadCipher.Decrypt(Encrypted, Iv, adata),
                    Symmetric, Aead
                );
            }
            else
            {
                var cipher = new BufferedCipher(
                    Helper.CfbCipherEngine(Symmetric)
                );
                cipher.Init(
                    false,
                    new ParametersWithIV(new KeyParameter(key), Iv)
                );
                var decrypted = cipher.Process(Encrypted);
                sessionKey = new SessionKey(
                    decrypted.Skip(1).ToArray(),
                    (SymmetricAlgorithm)decrypted[0]
                );
            }
        }

        return new SymmetricKeyEncryptedSessionKey(
            Version, S2k, Symmetric, Iv, Encrypted, Aead, sessionKey
        );
    }

    /// <summary>
    ///     Read SKESK packet from bytes
    /// </summary>
    public static SymmetricKeyEncryptedSessionKey FromBytes(byte[] bytes)
    {
        var offset = 0;
        var version = bytes[offset++];
        var isV6 = version == Version6;
        if (isV6)
            // A one-octet scalar octet count of the following 5 fields.
            offset++;

        // A one-octet number describing the symmetric algorithm used.
        var symmetric = (SymmetricAlgorithm)bytes[offset++];

        AeadAlgorithm? aead = null;
        var ivLength = 0;
        if (version >= Version5)
        {
            // A one-octet AEAD algorithm identifier.
            aead = (AeadAlgorithm)bytes[offset++];
            ivLength = Helper.AeadIvLength(aead);
            if (isV6)
                // A one-octet scalar octet count of the following field.
                offset++;
        }

        // A string-to-key (S2K) specifier, length as defined above.
        var s2kType = (S2kType)bytes[offset];
        IString2Key s2k = s2kType == S2kType.Argon2
            ? Argon2S2K.FromBytes(bytes.Skip(offset).ToArray())
            : GenericS2K.FromBytes(bytes.Skip(offset).ToArray());
        offset += s2k.Length;
        var iv = bytes.Skip(offset).Take(ivLength).ToArray();
        offset += ivLength;

        return new SymmetricKeyEncryptedSessionKey(
            version, s2k, symmetric, iv, bytes.Skip(offset).ToArray(), aead
        );
    }

    public static SymmetricKeyEncryptedSessionKey EncryptSessionKey(
        string password,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        ISessionKey? sessionKey = null,
        AeadAlgorithm? aead = null
    )
    {
        var aeadProtect = aead != null;
        var version = aeadProtect ? Version6 : Version4;
        var encryptSymmetric = sessionKey?.Symmetric ?? symmetric;
        Helper.AssertSymmetric(encryptSymmetric);

        var s2k = Helper.String2Key(
            aeadProtect ? S2kType.Argon2 : S2kType.Iterated
        );
        var keySize = (Helper.SymmetricKeySize(encryptSymmetric) + 7) >> 3;
        var key = s2k.ProduceKey(password, keySize);

        byte[] iv;
        byte[] encrypted;
        if (sessionKey != null)
        {
            if (aeadProtect)
            {
                byte[] adata =
                [
                    (int)PacketType.SymmetricKeyEncryptedSessionKey | 0xc0,
                    (byte)version,
                    (byte)encryptSymmetric,
                    (byte)aead!
                ];
                var kek = Helper.Hkdf(key, keySize, info: adata);
                iv = SecureRandom.GetNextBytes(new SecureRandom(), Helper.AeadIvLength(aead));
                var aeadCipher = new AeadCipher(
                    kek, (AeadAlgorithm)aead, encryptSymmetric
                );
                encrypted = aeadCipher.Encrypt(
                    sessionKey.EncryptionKey, iv, adata
                );
            }
            else
            {
                iv = [];
                var cipher = new BufferedCipher(
                    Helper.CfbCipherEngine(encryptSymmetric)
                );
                cipher.Init(
                    true,
                    new ParametersWithIV(
                        new KeyParameter(key),
                        new byte[Helper.SymmetricBlockSize(encryptSymmetric)]
                    )
                );
                encrypted = cipher.Process(sessionKey.ToBytes());
            }
        }
        else
        {
            iv = [];
            encrypted = [];
            sessionKey = new SessionKey(key, encryptSymmetric);
        }

        return new SymmetricKeyEncryptedSessionKey(
            version,
            s2k,
            encryptSymmetric,
            iv,
            encrypted,
            aead,
            sessionKey
        );
    }

    public override byte[] ToBytes()
    {
        return Version switch
        {
            Version6 =>
            [
                (byte)Version,
                (byte)(3 + S2k.Length + Iv.Length),
                (byte)Symmetric,
                ..Aead != null ? [(byte)Aead] : Array.Empty<byte>(),
                (byte)Iv.Length,
                ..S2k.ToBytes(),
                ..Iv,
                ..Encrypted
            ],
            Version5 =>
            [
                (byte)Version,
                (byte)Symmetric,
                ..Aead != null ? [(byte)Aead] : Array.Empty<byte>(),
                ..S2k.ToBytes(),
                ..Iv,
                ..Encrypted
            ],
            _ =>
            [
                (byte)Version,
                (byte)Symmetric,
                ..S2k.ToBytes(),
                ..Encrypted
            ]
        };
    }
}