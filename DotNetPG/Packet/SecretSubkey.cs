// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Type;

/// <summary>
///     Implementation a possibly encrypted sub private key (Tag 7).
/// </summary>
public class SecretSubkey : SecretKey, ISubkeyPacket
{
    private readonly PublicSubkey _publicSubkey;

    public SecretSubkey(
        PublicSubkey publicSubkey,
        byte[] keyData,
        byte[] iv,
        IKeyMaterial? keyMaterial = null,
        S2kUsage s2KUsage = S2kUsage.None,
        SymmetricAlgorithm? symmetric = null,
        IString2Key? s2K = null,
        AeadAlgorithm? aead = null
    ) : base(publicSubkey, keyData, iv, keyMaterial, s2KUsage, symmetric, s2K, aead)
    {
        Type = PacketType.SecretSubkey;
        _publicSubkey = publicSubkey;
    }

    /// <summary>
    ///     Read secret sub-key from bytes
    /// </summary>
    public new static SecretSubkey FromBytes(byte[] bytes)
    {
        var publicKey = PublicSubkey.FromBytes(bytes);
        var record = DecodeSecretKey(bytes, publicKey);
        return new SecretSubkey(
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
    ///     Generate secret sub-key packet
    /// </summary>
    public new static SecretSubkey Generate(
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
        var keyMaterial = GenerateKeyMaterial(algorithm, rsaKeySize, curve);
        return new SecretSubkey(
            new PublicSubkey(
                (int)version,
                time ?? DateTime.Now,
                algorithm,
                keyMaterial.PublicMaterial
            ),
            keyMaterial.ToBytes(), [], keyMaterial
        );
    }

    public override ISecretKeyPacket Encrypt(
        string passphrase,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        if (!IsDecrypted) return this;
        var record = EncryptKeyMaterial(passphrase, symmetric, aead);
        return new SecretSubkey(
            _publicSubkey,
            record.CipherText,
            record.Iv,
            KeyMaterial,
            aead != null ? S2kUsage.AeadProtect : S2kUsage.Cfb,
            symmetric,
            record.S2k,
            aead
        );
    }

    public override ISecretKeyPacket Decrypt(string passphrase)
    {
        return IsDecrypted
            ? this
            : new SecretSubkey(
                _publicSubkey,
                KeyData,
                Iv,
                DecryptKeyData(passphrase),
                S2kUsage,
                Symmetric,
                S2k,
                Aead
            );
    }
}