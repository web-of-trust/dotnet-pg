// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG;

using Common;
using Enum;
using Key;
using Type;

/// <summary>
///     OpenPGP class
///     Export high level API for developers.
/// </summary>
public sealed class OpenPGP
{
    /// <summary>
    /// Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
    /// The generated primary key will have signing capabilities.
    /// One subkey with encryption capabilities is also generated if `signOnly` is false.
    /// </summary>
    public static IPrivateKey GenerateKey(
        string[] userIds,
        string passphrase,
        KeyType keyType = KeyType.Rsa,
        RsaKeySize keySize = RsaKeySize.Normal,
        EcCurve curve = EcCurve.Secp521R1,
        int keyExpiry = 0,
        bool signOnly = false,
        DateTime? time = null
    )
    {
        return PrivateKey.Generate(
            userIds,
            passphrase,
            keyType,
            keySize,
            curve,
            keyExpiry,
            signOnly,
            time
        );
    }

    /// <summary>
    /// Read OpenPGP private key from armored string.
    /// </summary>
    public static IPrivateKey ReadPrivateKey(string armored)
    {
        return PrivateKey.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP private key from binary key data.
    /// </summary>
    public static IPrivateKey ReadPrivateKey(byte[] keyData)
    {
        return PrivateKey.FromBytes(keyData);
    }

    /// <summary>
    /// Read OpenPGP public key from armored string.
    /// </summary>
    public static IPublicKey ReadPublicKey(string armored)
    {
        return PublicKey.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP public key from binary key data.
    /// </summary>
    public static IPublicKey ReadPublicKey(byte[] keyData)
    {
        return PublicKey.FromBytes(keyData);
    }

    /// <summary>
    /// Read OpenPGP public key list from armored string.
    /// </summary>
    public static IPublicKey[] ReadPublicKeys(string armored)
    {
        return PublicKey.ReadPublicKeys(armored);
    }

    /// <summary>
    /// Read OpenPGP public key list from binary key data.
    /// </summary>
    public static IPublicKey[] ReadPublicKeys(byte[] keyData)
    {
        return PublicKey.ReadPublicKeys(keyData);
    }

    /// <summary>
    /// Armor multiple public key.
    /// </summary>
    public static string ArmorPublicKeys(IPublicKey[] keys)
    {
        return PublicKey.ArmorPublicKeys(keys);
    }

    /// <summary>
    /// Lock a private key with the given passphrase.
    /// The private key must be decrypted.
    /// </summary>
    public static IPrivateKey EncryptPrivateKey(
        IPrivateKey privateKey,
        string passphrase,
        string[]? subkeyPassphrases = null,
        SymmetricAlgorithm? symmetric = null,
        AeadAlgorithm? aead = null
    )
    {
        return privateKey.Encrypt(
            passphrase,
            subkeyPassphrases,
            symmetric ?? Config.PreferredSymmetric,
            aead
        );
    }

    /// <summary>
    /// Read & unlock OpenPGP private key with the given passphrase.
    /// </summary>
    public static IPrivateKey DecryptPrivateKey(
        string armored,
        string passphrase,
        string[]? subkeyPassphrases = null
    )
    {
        return ReadPrivateKey(armored).Decrypt(passphrase, subkeyPassphrases);
    }

    /// <summary>
    /// Read & unlock OpenPGP private key with the given passphrase.
    /// </summary>
    public static IPrivateKey DecryptPrivateKey(
        byte[] keyData,
        string passphrase,
        string[]? subkeyPassphrases = null
    )
    {
        return ReadPrivateKey(keyData).Decrypt(passphrase, subkeyPassphrases);
    }

    /// <summary>
    /// Certify an OpenPGP key by a private key.
    /// </summary>
    /// <returns>Return clone of the key object with the new certification added.</returns>
    public static IKey CertifyKey(
        IPrivateKey privateKey,
        IKey key,
        DateTime? time = null
    )
    {
        return privateKey.CertifyKey(key, time);
    }

    /// <summary>
    /// Revoke an OpenPGP key by a private key.
    /// </summary>
    /// <returns>Return clone of the key object with the new revocation signature added.</returns>
    public static IKey RevokeKey(
        IPrivateKey privateKey,
        IKey key,
        string revocationReason,
        RevocationReasonTag reasonTag,
        DateTime? time = null
    )
    {
        return privateKey.RevokeKey(key, revocationReason, reasonTag, time);
    }
}
