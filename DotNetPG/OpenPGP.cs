// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG;

using Common;
using Enum;
using Key;
using Message;
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
    public static IList<IPublicKey> ReadPublicKeys(string armored)
    {
        return PublicKey.ReadPublicKeys(armored);
    }

    /// <summary>
    /// Read OpenPGP public key list from binary key data.
    /// </summary>
    public static IList<IPublicKey> ReadPublicKeys(byte[] keyData)
    {
        return PublicKey.ReadPublicKeys(keyData);
    }

    /// <summary>
    /// Armor multiple public key.
    /// </summary>
    public static string ArmorPublicKeys(IList<IPublicKey> keys)
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
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        return privateKey.RevokeKey(key, revocationReason, reasonTag, time);
    }

    /// <summary>
    /// Read OpenPGP signature from armored string.
    /// </summary>
    /// <returns>Return a signature object.</returns>
    public static ISignature ReadSignature(string armored)
    {
        return Signature.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP signature from binary.
    /// </summary>
    /// <returns>Return a signature object.</returns>
    public static ISignature ReadSignature(byte[] signatureData)
    {
        return Signature.FromBytes(signatureData);
    }

    /// <summary>
    /// Read OpenPGP signed message from armored string.
    /// </summary>
    /// <returns>Return a signed message object.</returns>
    public static ISignedMessage ReadSignedMessage(string armored)
    {
        return SignedMessage.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP encrypted message from armored string.
    /// </summary>
    /// <returns>Return an encrypted message object.</returns>
    public static IEncryptedMessage ReadEncryptedMessage(string armored)
    {
        return EncryptedMessage.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP encrypted message from binary.
    /// </summary>
    /// <returns>Return an encrypted message object.</returns>
    public static IEncryptedMessage ReadEncryptedMessage(byte[] messageData)
    {
        return EncryptedMessage.FromBytes(messageData);
    }

    /// <summary>
    /// Read OpenPGP literal message from armored string.
    /// </summary>
    /// <returns>Return a literal message object.</returns>
    public static ILiteralMessage ReadLiteralMessage(string armored)
    {
        return LiteralMessage.FromArmored(armored);
    }

    /// <summary>
    /// Read OpenPGP literal message from binary.
    /// </summary>
    /// <returns>Return a literal message object.</returns>
    public static ILiteralMessage ReadLiteralMessage(byte[] messageData)
    {
        return LiteralMessage.FromBytes(messageData);
    }

    /// <summary>
    /// Create new cleartext message object from text.
    /// </summary>
    public static ICleartextMessage CreateCleartextMessage(string text)
    {
        return new CleartextMessage(text);
    }

    /// <summary>
    /// Create new literal message object from literal data.
    /// </summary>
    public static ILiteralMessage CreateLiteralMessage(
        byte[] data,
        string filename = "",
        DateTime? time = null
    )
    {
        return LiteralMessage.FromLiteralData(data, filename, time);
    }

    /// <summary>
    /// Create new literal message object from text.
    /// </summary>
    public static ILiteralMessage CreateLiteralMessage(
        string text
    )
    {
        return LiteralMessage.FromText(text);
    }

    /// <summary>
    /// Sign a cleartext message.
    /// </summary>
    /// <returns>Return a signed message object.</returns>
    public static ISignedMessage SignCleartext(
        string text,
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        return CreateCleartextMessage(text).Sign(signingKeys, recipients, notationData, time);
    }

    /// <summary>
    /// Sign a cleartext message & return detached signature.
    /// </summary>
    public static ISignature SignDetachedCleartext(
        string text,
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        return CreateCleartextMessage(text).SignDetached(signingKeys, recipients, notationData, time);
    }

    /// <summary>
    /// Sign a message & return signed literal message.
    /// </summary>
    public static ILiteralMessage Sign(
        ILiteralMessage message,
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        return message.Sign(signingKeys, recipients, notationData, time);
    }

    /// <summary>
    /// Sign a message & return detached signature.
    /// </summary>
    public static ISignature SignDetached(
        ILiteralMessage message,
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        return message.SignDetached(signingKeys, recipients, notationData, time);
    }

    /// <summary>
    /// Verify signatures of cleartext signed message.
    /// </summary>
    /// <returns>Return verifications.</returns>
    public static IList<IVerification> Verify(
        string armored,
        IList<IKey> verificationKeys,
        DateTime? time = null
    )
    {
        return ReadSignedMessage(armored).Verify(verificationKeys, time);
    }

    /// <summary>
    /// Verify detached signatures of cleartext message.
    /// </summary>
    /// <returns>Return verifications.</returns>
    public static IList<IVerification> VerifyDetached(
        string text,
        string signature,
        IList<IKey> verificationKeys,
        DateTime? time = null
    )
    {
        return CreateCleartextMessage(text).VerifyDetached(verificationKeys, Signature.FromArmored(signature), time);
    }

    /// <summary>
    /// Encrypt a message using public keys, passwords or both at once.
    /// At least one of `encryptionKeys`, `passwords`must be specified.
    /// If signing keys are specified, those will be used to sign the message.
    /// </summary>
    public static IEncryptedMessage Encrypt(
        ILiteralMessage message,
        IList<IKey> encryptionKeys,
        IList<string> passwords,
        IList<IPrivateKey> signingKeys,
        SymmetricAlgorithm?  symmetric = null,
        CompressionAlgorithm? compression = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        if (signingKeys.Count == 0)
        {
            return message.Compress(compression ?? Config.PreferredCompression).Encrypt(
                encryptionKeys, passwords, symmetric ?? Config.PreferredSymmetric
            );
        }
        else
        {
            return message.Sign(
                signingKeys, encryptionKeys, notationData, time
            ).Compress(compression ?? Config.PreferredCompression).Encrypt(
                encryptionKeys, passwords, symmetric ?? Config.PreferredSymmetric
            );
        }
    }

    /// <summary>
    /// Decrypt a message with the user's private keys, or passwords.
    /// One of `decryptionKeys` or `passwords` must be specified.
    /// </summary>
    public static ILiteralMessage Decrypt(
        IEncryptedMessage message,
        IList<IPrivateKey> decryptionKeys,
        IList<string> password
    )
    {
        return message.Decrypt(decryptionKeys, password);
    }

    /// <summary>
    /// Decrypt a armored encrypted string with
    /// the user's private keys, or passwords.
    /// One of `decryptionKeys` or `passwords` must be specified.
    /// </summary>
    public static ILiteralMessage Decrypt(
        string messageData,
        IList<IPrivateKey> decryptionKeys,
        IList<string> passwords
    )
    {
        return ReadEncryptedMessage(messageData).Decrypt(decryptionKeys, passwords);
    }

    /// <summary>
    /// Generate a new session key object.
    /// Taking the algorithm preferences of the passed encryption keys, if any.
    /// </summary>
    public static ISessionKey GenerateSessionKey(
        IList<IKey> encryptionKeys, SymmetricAlgorithm? symmetric = null
    )
    {
        return LiteralMessage.GenerateSessionKey(encryptionKeys, symmetric ?? Config.PreferredSymmetric);
    }

    /// <summary>
    /// Encrypt a session key either with public keys, passwords, or both at once.
    /// </summary>
    public static IPacketList EncryptSessionKey(
        ISessionKey sessionKey,
        IList<IKey> encryptionKeys,
        IList<string> passwords
    )
    {
        return LiteralMessage.EncryptSessionKey(sessionKey, encryptionKeys, passwords);
    }

    /// <summary>
    /// Decrypt encrypted session keys.
    /// Using private keys or passwords (not both).
    /// </summary>
    public static ISessionKey DecryptSessionKey(
        IPacketList packetList,
        IList<IPrivateKey> decryptionKeys,
        IList<string> passwords
    )
    {
        return EncryptedMessage.DecryptSessionKey(packetList, decryptionKeys, passwords);
    }
}
