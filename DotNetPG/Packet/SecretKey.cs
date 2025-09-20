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
using Org.BouncyCastle.Utilities;

/// <summary>
///     Implementation a possibly encrypted private key (Tag 5).
/// </summary>
public class SecretKey : BasePacket, ISecretKeyPacket
{
    private readonly PublicKey _publicKey;

    public SecretKey(
        PublicKey publicKey,
        byte[] keyData,
        byte[] iv,
        IKeyMaterial? keyMaterial = null,
        S2kUsage s2kUsage = S2kUsage.None,
        SymmetricAlgorithm? symmetric = null,
        IString2Key? s2k = null,
        AeadAlgorithm? aead = null
    ) : base(PacketType.SecretKey)
    {
        _publicKey = publicKey;
        KeyData = keyData;
        Iv = iv;
        SecretKeyMaterial = keyMaterial;
        S2kUsage = s2kUsage;
        Symmetric = symmetric;
        S2k = s2k;
        Aead = aead;

        if (_publicKey.IsV6Key && S2kUsage == S2kUsage.MalleableCfb)
            throw new ArgumentException(
                $"{S2kUsage} s2k usage cannot be used with v6 key packet."
            );
    }

    public byte[] KeyData { get; }

    public byte[] Iv { get; }

    public IPublicKeyPacket PublicKey => _publicKey;

    public IKeyMaterial? SecretKeyMaterial { get; }

    public IKeyMaterial KeyMaterial => _publicKey.KeyMaterial;

    public S2kUsage S2kUsage { get; }

    public SymmetricAlgorithm? Symmetric { get; }

    public IString2Key? S2k { get; }

    public AeadAlgorithm? Aead { get; }

    public int Version => _publicKey.Version;

    public DateTime CreationTime => _publicKey.CreationTime;

    public KeyAlgorithm KeyAlgorithm => _publicKey.KeyAlgorithm;

    public byte[] Fingerprint => _publicKey.Fingerprint;

    public byte[] KeyId => _publicKey.KeyId;

    public int KeyLength => _publicKey.KeyLength;

    public bool IsSigningKey => _publicKey.IsSigningKey;

    public bool IsEncryptionKey => _publicKey.IsEncryptionKey;

    public bool IsV6Key => _publicKey.IsV6Key;

    public HashAlgorithm GetPreferredHash(HashAlgorithm? algorithm = null)
    {
        return _publicKey.GetPreferredHash(algorithm);
    }

    public bool IsEncrypted => S2k != null && Symmetric != null && S2kUsage != S2kUsage.None;

    public bool IsDecrypted => SecretKeyMaterial != null;

    public override byte[] ToBytes()
    {
        if (!IsEncrypted)
            return
            [
                .._publicKey.ToBytes(),
                (byte)S2kUsage.None,
                ..KeyData,
                ..IsV6Key ? [] : Helper.ComputeChecksum(KeyData)
            ];

        byte[] optBytes =
        [
            (byte)Symmetric!,
            ..Aead != null ? [(byte)Aead] : Array.Empty<byte>(),
            ..IsV6Key ? [(byte)S2k!.Length] : Array.Empty<byte>(),
            ..S2k!.ToBytes(),
            ..Iv
        ];

        return
        [
            .._publicKey.ToBytes(),
            (byte)S2kUsage,
            ..IsV6Key ? [(byte)optBytes.Length] : Array.Empty<byte>(),
            ..optBytes,
            ..KeyData
        ];
    }

    public byte[] SignBytes()
    {
        return _publicKey.SignBytes();
    }

    public virtual ISecretKeyPacket Encrypt(
        string passphrase,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        if (!IsDecrypted) return this;
        var record = EncryptKeyMaterial(passphrase, symmetric, aead);
        return new SecretKey(
            _publicKey,
            record.CipherText,
            record.Iv,
            SecretKeyMaterial,
            aead != null ? S2kUsage.AeadProtect : S2kUsage.Cfb,
            symmetric,
            record.S2k,
            aead
        );
    }

    public virtual ISecretKeyPacket Decrypt(string passphrase)
    {
        return IsDecrypted
            ? this
            : new SecretKey(
                _publicKey,
                KeyData,
                Iv,
                DecryptKeyData(passphrase),
                S2kUsage,
                Symmetric,
                S2k,
                Aead
            );
    }

    /// <summary>
    ///     Read secret key from bytes
    /// </summary>
    public static SecretKey FromBytes(byte[] bytes)
    {
        var publicKey = Packet.PublicKey.FromBytes(bytes);
        var record = DecodeSecretKey(bytes, publicKey);
        return new SecretKey(
            publicKey,
            record.KeyData,
            record.Iv,
            record.KeyMaterial,
            record.S2kUsage,
            record.Symmetric,
            record.S2k,
            record.Aead
        );
    }

    /// <summary>
    ///     Generate secret key packet
    /// </summary>
    public static SecretKey Generate(
        KeyAlgorithm algorithm = KeyAlgorithm.RsaGeneral,
        RsaKeySize rsaKeySize = RsaKeySize.Normal,
        EcCurve curve = EcCurve.Secp521R1,
        DateTime? time = null
    )
    {
        var version = algorithm switch
        {
            KeyAlgorithm.X25519 or
                KeyAlgorithm.X448 or
                KeyAlgorithm.Ed25519 or
                KeyAlgorithm.Ed448 => KeyVersion.V6,
            _ => Config.PresetRfc == PresetRfc.Rfc9580 ? KeyVersion.V6 : KeyVersion.V4
        };
        var keyMaterial = GenerateKeyMaterial(
            algorithm, rsaKeySize, curve
        );
        return new SecretKey(
            new PublicKey(
                (int)version,
                time ?? DateTime.Now,
                algorithm,
                keyMaterial.PublicMaterial
            ),
            keyMaterial.ToBytes(),
            [],
            keyMaterial
        );
    }

    protected (byte[] CipherText, byte[] Iv, IString2Key S2k) EncryptKeyMaterial(
        string passphrase,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        Helper.AssertSymmetric(symmetric);

        var aeadProtect = aead != null;
        if (aeadProtect && !IsV6Key)
            throw new Exception(
                $"Using AEAD with version {Version} of the key packet is not allowed."
            );
        var s2k = Helper.String2Key(
            aeadProtect ? S2kType.Argon2 : S2kType.Iterated
        );
        var iv = SecureRandom.GetNextBytes(
            new SecureRandom(),
            aeadProtect ? Helper.AeadIvLength(aead) : Helper.SymmetricBlockSize(symmetric)
        );

        var packetType = TypeByte;
        var kek = ProduceEncryptionKey(
            passphrase, packetType, symmetric, s2k, aead
        );
        var clearText = SecretKeyMaterial?.ToBytes() ?? [];
        byte[] cipherText;

        if (aeadProtect)
        {
            var aeadCipher = new AeadCipher(kek, (AeadAlgorithm)aead!, symmetric);
            cipherText = aeadCipher.Encrypt(
                clearText, iv, [TypeByte, ..PublicKey.ToBytes()]
            );
        }
        else
        {
            var cipher = new BufferedCipher(Helper.CfbCipherEngine(symmetric));
            cipher.Init(
                true, new ParametersWithIV(new KeyParameter(kek), iv)
            );
            cipherText = cipher.Process([
                ..clearText,
                ..DigestUtilities.CalculateDigest(
                    nameof(HashAlgorithm.Sha1), clearText
                )
            ]);
        }

        return (cipherText, iv, s2k);
    }

    protected IKeyMaterial DecryptKeyData(string passphrase)
    {
        if (!IsEncrypted) return ReadKeyMaterial(KeyData, _publicKey);

        byte[] clearText;
        var kek = ProduceEncryptionKey(
            passphrase, TypeByte, (SymmetricAlgorithm)Symmetric!, S2k, Aead
        );
        if (Aead != null)
        {
            var aeadCipher = new AeadCipher(
                kek, (AeadAlgorithm)Aead!, (SymmetricAlgorithm)Symmetric
            );
            clearText = aeadCipher.Decrypt(
                KeyData, Iv, [TypeByte, .._publicKey.ToBytes()]
            );
        }
        else
        {
            var iv = Iv.Length > 0 ? Iv : new byte[Helper.SymmetricBlockSize(Symmetric)];
            var cipher = new BufferedCipher(
                Helper.CfbCipherEngine(Symmetric)
            );
            cipher.Init(
                false, new ParametersWithIV(new KeyParameter(kek), iv)
            );
            var textWithHash = cipher.Process(KeyData);
            var length = textWithHash.Length - Helper.HashDigestSize(HashAlgorithm.Sha1);
            var hashText = textWithHash.Skip(length).ToArray();
            clearText = textWithHash.Take(length).ToArray();
            var hashed = DigestUtilities.CalculateDigest(
                nameof(HashAlgorithm.Sha1), clearText
            );
            if (!Arrays.AreEqual(hashed, hashText)) throw new Exception("Incorrect key passphrase.");
        }

        return ReadKeyMaterial(clearText, _publicKey);
    }

    /// <summary>
    ///     Derive encryption key
    /// </summary>
    private static byte[] ProduceEncryptionKey(
        string passphrase,
        byte packetType,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        IString2Key? s2k = null,
        AeadAlgorithm? aead = null
    )
    {
        if (s2k?.Type == S2kType.Argon2 && aead == null)
            throw new Exception(
                "Using Argon2 S2K without AEAD is not allowed."
            );

        var keySize = (Helper.SymmetricKeySize(symmetric) + 7) >> 3;
        var derivedKey = s2k?.ProduceKey(passphrase, keySize) ?? new byte[keySize];
        return aead == null
            ? derivedKey
            : Helper.Hkdf(
                derivedKey,
                keySize,
                info: [packetType, (byte)KeyVersion.V6, (byte)symmetric, (byte)aead!]
            );
    }

    /// <summary>
    ///     Generate secret key material
    /// </summary>
    protected static IKeyMaterial GenerateKeyMaterial(
        KeyAlgorithm algorithm = KeyAlgorithm.RsaGeneral,
        RsaKeySize rsaKeySize = RsaKeySize.Normal,
        EcCurve curve = EcCurve.Secp521R1
    )
    {
        return algorithm switch
        {
            KeyAlgorithm.RsaGeneral or
                KeyAlgorithm.RsaEncrypt or
                KeyAlgorithm.RsaSign => RsaSecretKeyMaterial.Generate(rsaKeySize),
            KeyAlgorithm.EcDh => EcDhSecretKeyMaterial.Generate(curve),
            KeyAlgorithm.EcDsa => EcDsaSecretKeyMaterial.Generate(curve),
            KeyAlgorithm.EdDsaLegacy => EdDsaLegacySecretKeyMaterial.Generate(),
            KeyAlgorithm.X25519 => MontgomerySecretKeyMaterial.Generate(MontgomeryCurve.Curve25519),
            KeyAlgorithm.X448 => MontgomerySecretKeyMaterial.Generate(MontgomeryCurve.Curve448),
            KeyAlgorithm.Ed25519 => EdDsaSecretKeyMaterial.Generate(EdDsaCurve.Ed25519),
            KeyAlgorithm.Ed448 => EdDsaSecretKeyMaterial.Generate(EdDsaCurve.Ed448),
            _ => throw new Exception($"Key algorithm {algorithm} is unsupported.")
        };
    }

    protected static (byte[] KeyData, byte[] Iv, IKeyMaterial? KeyMaterial, S2kUsage S2kUsage, SymmetricAlgorithm?
        Symmetric, IString2Key? S2k, AeadAlgorithm? Aead) DecodeSecretKey(byte[] bytes, IPublicKeyPacket publicKey)
    {
        var offset = publicKey.ToBytes().Length;
        var s2kUsage = (S2kUsage)bytes[offset++];

        // Only for a version 6 packet where the secret key material encrypted
        if (publicKey.IsV6Key && s2kUsage != S2kUsage.None) offset++;

        IString2Key? s2k = null;
        SymmetricAlgorithm? symmetric = null;
        AeadAlgorithm? aead = null;
        switch (s2kUsage)
        {
            case S2kUsage.AeadProtect:
            case S2kUsage.Cfb:
            case S2kUsage.MalleableCfb:
                // one-octet symmetric encryption algorithm.
                symmetric = (SymmetricAlgorithm)bytes[offset++];

                // If s2k usage octet was 253, a one-octet AEAD algorithm.
                if (s2kUsage == S2kUsage.AeadProtect) aead = (AeadAlgorithm)bytes[offset++];

                // Only for a version 6 packet, and if string-to-key usage
                // octet was 253 or 254, an one-octet count of the following field.
                if (publicKey.IsV6Key && s2kUsage is S2kUsage.AeadProtect or S2kUsage.Cfb) offset++;

                var s2kType = (S2kType)bytes[offset];
                s2k = s2kType switch
                {
                    S2kType.Argon2 => Argon2S2K.FromBytes(bytes.Skip(offset).ToArray()),
                    _ => GenericS2K.FromBytes(bytes.Skip(offset).ToArray())
                };
                offset += s2k.Length;
                break;
            default:
                symmetric = SymmetricAlgorithm.Plaintext;
                break;
        }

        byte[] iv;
        if (aead != null)
            iv = bytes.Skip(offset).Take(Helper.AeadIvLength(aead)).ToArray();
        else
            iv = bytes.Skip(offset).Take(Helper.SymmetricBlockSize(symmetric)).ToArray();
        offset += iv.Length;

        IKeyMaterial? keyMaterial = null;
        var keyData = bytes.Skip(offset).ToArray();
        if (s2kUsage == S2kUsage.None)
        {
            if (!publicKey.IsV6Key)
            {
                var checksum = keyData.Skip(keyData.Length - 2).ToArray();
                keyData = keyData.Take(keyData.Length - 2).ToArray();
                if (!Arrays.AreEqual(checksum, Helper.ComputeChecksum(keyData)))
                {
                    throw new Exception("Key checksum doesn't match.");
                }
            }

            keyMaterial = ReadKeyMaterial(keyData, publicKey);
        }

        return (keyData, iv, keyMaterial, s2kUsage, symmetric, s2k, aead);
    }

    private static IKeyMaterial ReadKeyMaterial(byte[] bytes, IPublicKeyPacket publicKey)
    {
        IKeyMaterial keyMaterial = publicKey.KeyMaterial switch
        {
            RsaPublicKeyMaterial rsaMaterial => RsaSecretKeyMaterial.FromBytes(bytes, rsaMaterial),
            EcDhPublicKeyMaterial ecDhMaterial => EcDhSecretKeyMaterial.FromBytes(bytes, ecDhMaterial),
            EcDsaPublicKeyMaterial ecDsaMaterial => EcDsaSecretKeyMaterial.FromBytes(bytes, ecDsaMaterial),
            EdDsaLegacyPublicKeyMaterial ecDsaLegacyMaterial => EdDsaLegacySecretKeyMaterial.FromBytes(bytes,
                ecDsaLegacyMaterial),
            MontgomeryPublicKeyMaterial montgomeryMaterial => MontgomerySecretKeyMaterial.FromBytes(bytes,
                montgomeryMaterial),
            EdDsaPublicKeyMaterial ecDsaMaterial => EdDsaSecretKeyMaterial.FromBytes(bytes, ecDsaMaterial),
            _ => throw new ArgumentException($"Key algorithm {publicKey.KeyAlgorithm} is unsupported.")
        };

        return !keyMaterial.IsValid() ? throw new Exception("Key material is not consistent.") : keyMaterial;
    }
}