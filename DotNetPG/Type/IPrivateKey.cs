// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Private key interface.
/// </summary>
public interface IPrivateKey : IArmorable, IKey
{
    /// <summary>
    ///     Return true if the key packet is encrypted.
    /// </summary>
    bool IsEncrypted { get; }

    /// <summary>
    ///     Return true if the key packet is decrypted.
    /// </summary>
    bool IsDecrypted { get; }

    /// <summary>
    ///     Return true if the key packet is aead protected.
    /// </summary>
    bool AeadProtected { get; }

    /// <summary>
    ///     Get secret key packet.
    /// </summary>
    ISecretKeyPacket SecretKeyPacket { get; }

    /// <summary>
    ///     Get key as public key
    /// </summary>
    IPublicKey PublicKey { get; }

    /// <summary>
    ///     Lock a private key with the given passphrase.
    ///     This method does not change the original key.
    /// </summary>
    IPrivateKey Encrypt(
        string passphrase,
        string[]? subkeyPassphrases = null,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    );

    /// <summary>
    ///     Unlock a private key with the given passphrase.
    ///     This method does not change the original key.
    /// </summary>
    IPrivateKey Decrypt(string passphrase, string[]? subkeyPassphrases = null);

    /// <summary>
    ///     Add userIDs to the key.
    ///     Return a clone of the key object with the new userIDs added.
    /// </summary>
    IPrivateKey AddUsers(string[] userIds);

    /// <summary>
    ///     Generate a new OpenPGP subkey.
    ///     Return a clone of the key object with the new subkey added.
    /// </summary>
    IPrivateKey AddSubkey(
        string passphrase,
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.RsaGeneral,
        RsaKeySize rsaKeySize = RsaKeySize.Normal,
        EcCurve ecCurve = EcCurve.Secp521R1,
        int keyExpiry = 0,
        bool forSigning = false,
        DateTime? time = null
    );

    /// <summary>
    ///     Certify an OpenPGP key.
    ///     Return clone of the key object with the new certification added.
    /// </summary>
    IKey CertifyKey(IKey key, DateTime? time = null);

    /// <summary>
    ///     Revoke an OpenPGP key.
    ///     Return clone of the key object with the new revocation signature added.
    /// </summary>
    IKey RevokeKey(
        IKey key,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );

    /// <summary>
    ///     Revoke user & return a clone of the key object with the new revoked user.
    /// </summary>
    IKey RevokeUser(
        string userId,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );

    /// <summary>
    ///     Revoke subkey & return a clone of the key object with the new revoked subkey.
    /// </summary>
    IKey RevokeSubkey(
        string userId,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );
}