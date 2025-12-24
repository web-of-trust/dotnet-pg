// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Common;
using Enum;
using Packet;
using Type;
using Org.BouncyCastle.Utilities;

public class PrivateKey : BaseKey, IPrivateKey
{
    public PrivateKey(IPacketList packetList) : base(packetList)
    {
        if (KeyPacket is ISecretKeyPacket keyPacket)
        {
            SecretKeyPacket = keyPacket;
        }
        else
        {
            throw new Exception("Key packet is not a secret key.");
        }
    }

    public PrivateKey(
        ISecretKeyPacket keyPacket,
        IList<ISignaturePacket> revocationSignatures,
        IList<ISignaturePacket> directSignatures,
        IList<IUser> users,
        IList<ISubkey> subkeys
    ) : base(keyPacket, revocationSignatures, directSignatures, users, subkeys)
    {
        SecretKeyPacket = keyPacket;
    }

    public static IPrivateKey FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static IPrivateKey FromBytes(byte[] bytes)
    {
        return new PrivateKey(Packet.PacketList.Decode(bytes));
    }

    public static IPrivateKey Generate(
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
        if (Arrays.IsNullOrEmpty(userIds) || passphrase.Length == 0)
        {
            throw new ArgumentException(
                "UserIDs and passphrase are required for key generation."
            );
        }

        var keyAlgorithm = keyType switch
        {
            KeyType.Ecc => curve == EcCurve.Ed25519 ? KeyAlgorithm.EdDsaLegacy : KeyAlgorithm.EcDsa,
            KeyType.Curve25519 => KeyAlgorithm.Ed25519,
            KeyType.Curve448 => KeyAlgorithm.Ed448,
            _ => KeyAlgorithm.RsaGeneral
        };

        var secretKey = SecretKey.Generate(keyAlgorithm, keySize, curve, time);
        AeadAlgorithm? aead = secretKey.IsV6Key && Config.AeadProtect ? Config.PreferredAead : null;

        IList<IPacket> packets = [secretKey.Encrypt(passphrase, Config.PreferredSymmetric, aead)];
        if (secretKey.IsV6Key)
        {
            // Wrap secret key with direct key signature
            packets.Add(SignaturePacket.CreateDirectKeySignature(secretKey, keyExpiry, time));
        }

        // Wrap user id with certificate signature
        var index = 0;
        foreach (var userId in userIds)
        {
            var userPacket = new UserId(userId);
            packets.Add(userPacket);
            packets.Add(SignaturePacket.CreateSelfCertificate(
                secretKey,
                userPacket,
                index == 0,
                keyExpiry,
                time
            ));
            index++;
        }

        if (!signOnly)
        {
            // Generate & Wrap secret subkey with binding signature
            var subkeyAlgorithm = keyType switch
            {
                KeyType.Ecc => KeyAlgorithm.EcDh,
                KeyType.Curve25519 => KeyAlgorithm.X25519,
                KeyType.Curve448 => KeyAlgorithm.X448,
                _ => KeyAlgorithm.RsaGeneral
            };
            var subkeyCurve = keyAlgorithm == KeyAlgorithm.EdDsaLegacy ? EcCurve.Curve25519 : curve;
            var secretSubkey = SecretSubkey.Generate(subkeyAlgorithm, keySize, subkeyCurve, time);
            packets.Add(secretSubkey.Encrypt(passphrase, Config.PreferredSymmetric, aead));
            packets.Add(SignaturePacket.CreateSubkeyBinding(
                secretKey,
                secretSubkey,
                keyExpiry,
                false,
                time
            ));
        }
        return new PrivateKey(new PacketList(packets));
    }

    public bool IsEncrypted => SecretKeyPacket.IsEncrypted;

    public bool IsDecrypted => SecretKeyPacket.IsDecrypted;

    public bool AeadProtected => SecretKeyPacket.Aead != null;

    public ISecretKeyPacket SecretKeyPacket { get; }

    public IPublicKey PublicKey
    {
        get
        {
            IList<IPacket> packets = [];
            foreach (var packet in PacketList.Packets)
            {
                if (packet is ISecretKeyPacket keyPacket)
                {
                    packets.Add(keyPacket.PublicKey);
                }
                else
                {
                    packets.Add(packet);
                }
            }

            return new PublicKey(new PacketList(packets));
        }
    }

    public string Armor() => Common.Armor.Encode(ArmorType.PrivateKey, PacketList.Encode(), []);

    public override IKey CertifyBy(IPrivateKey signKey, DateTime? time = null)
    {
        var primaryUser = PrimaryUser;
        if (primaryUser == null) return this;

        var certifiedUser = primaryUser.CertifyBy(signKey, time);
        var certifiedUserId = certifiedUser.UserId;

        IList<IUser> users = [certifiedUser];
        foreach (var user in Users)
        {
            if (user.UserId != certifiedUserId)
            {
                users.Add(user);
            }
        }
        return new PrivateKey(
            SecretKeyPacket,
            RevocationSignatures,
            DirectSignatures,
            users.ToArray(),
            Subkeys
        );
    }

    public override IKey RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        return new PrivateKey(
            SecretKeyPacket,
            [
                SignaturePacket.CreateKeyRevocation(
                    signKey.SecretKeyPacket,
                    KeyPacket,
                    revocationReason,
                    reasonTag,
                    time
                ),
                ..RevocationSignatures
            ],
            DirectSignatures,
            Users,
            Subkeys
        );
    }

    public IPrivateKey Encrypt(
        string passphrase,
        string[]? subkeyPassphrases = null,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        if (passphrase.Length == 0)
        {
            throw new ArgumentException("Passphrase are required for key encryption.");
        }
        if (!IsDecrypted)
        {
            throw new Exception("Private key must be decrypted before encrypting.");
        }

        var subkeys = Subkeys.ToList();
        foreach (var subkey in subkeys)
        {
            var index = subkeys.IndexOf(subkey);
            var subkeyPass = subkeyPassphrases?[index] ?? passphrase;
            if (subkeyPass != "" && subkey.KeyPacket is SecretSubkey secretKeyPacket)
            {
                subkeys[index] = new Subkey(
                    this,
                    (SecretSubkey)secretKeyPacket.Encrypt(subkeyPass, symmetric, aead),
                    subkey.RevocationSignatures,
                    subkey.BindingSignatures
                );
            }
        }

        return new PrivateKey(
            SecretKeyPacket.Encrypt(passphrase, symmetric, aead),
            RevocationSignatures,
            DirectSignatures,
            Users,
            subkeys.ToArray()
        );
    }

    public IPrivateKey Decrypt(string passphrase, string[]? subkeyPassphrases = null)
    {
        if (passphrase.Length == 0)
        {
            throw new ArgumentException("Passphrase are required for key decryption.");
        }
        var subkeys = Subkeys.ToList();
        foreach (var subkey in subkeys)
        {
            var index = subkeys.IndexOf(subkey);
            var subkeyPass = subkeyPassphrases?[index] ?? passphrase;
            if (subkeyPass != "" && subkey.KeyPacket is SecretSubkey secretKeyPacket)
            {
                subkeys[index] = new Subkey(
                    this,
                    (SecretSubkey)secretKeyPacket.Decrypt(subkeyPass),
                    subkey.RevocationSignatures,
                    subkey.BindingSignatures
                );
            }
        }
        return new PrivateKey(
            SecretKeyPacket.Decrypt(passphrase),
            RevocationSignatures,
            DirectSignatures,
            Users,
            subkeys.ToArray()
        );
    }

    public IPrivateKey AddUsers(string[] userIds)
    {
        if (Arrays.IsNullOrEmpty(userIds))
        {
            throw new ArgumentException("UserIds are required.");
        }

        var users = Users.ToList();
        foreach (var userId in userIds)
        {
            var packet = new UserId(userId);
            users.Add(new User(
                this,
                packet,
                [],
                [SignaturePacket.CreateSelfCertificate(SecretKeyPacket, packet)],
                []
            ));
        }
        return new PrivateKey(
            SecretKeyPacket,
            RevocationSignatures,
            DirectSignatures,
            users.ToArray(),
            Subkeys
        );
    }

    public IPrivateKey AddSubkey(
        string passphrase,
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.RsaGeneral,
        RsaKeySize rsaKeySize = RsaKeySize.Normal,
        EcCurve ecCurve = EcCurve.Secp521R1,
        int keyExpiry = 0,
        bool forSigning = false,
        DateTime? time = null
    )
    {
        if (passphrase.Length == 0)
        {
            throw new ArgumentException("Passphrase is required for key generation.");
        }
        AeadAlgorithm? aead = null;
        if (SecretKeyPacket.IsV6Key && Config.AeadProtect)
        {
            aead = Config.PreferredAead;
        }

        var secretSubkey = (SecretSubkey)SecretSubkey.Generate(keyAlgorithm, rsaKeySize, ecCurve, time)
            .Encrypt(passphrase, Config.PreferredSymmetric, aead);
        var subkey = new Subkey(
            this, 
            secretSubkey, 
            [], 
            [SignaturePacket.CreateSubkeyBinding(
                SecretKeyPacket,
                secretSubkey,
                keyExpiry,
                forSigning,
                time
            )]
        );
        return new PrivateKey(
            SecretKeyPacket,
            RevocationSignatures,
            DirectSignatures,
            Users,
            [subkey, ..Subkeys]
        );
    }

    public IKey CertifyKey(IKey key, DateTime? time = null)
    {
        return key.CertifyBy(this, time);
    }

    public IKey RevokeKey(
        IKey key,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        return key.RevokeBy(this, revocationReason, reasonTag, time);
    }

    public IPrivateKey RevokeUser(
        string userId,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        var users = Users.ToList();
        foreach (var user in users)
        {
            if (user.UserId == userId)
            {
                var index = users.IndexOf(user);
                users[index] = user.RevokeBy(this, revocationReason, reasonTag, time);
            }
        }
        return new PrivateKey(
            SecretKeyPacket,
            RevocationSignatures,
            DirectSignatures,
            users.ToArray(),
            Subkeys
        );
    }

    public IPrivateKey RevokeSubkey(
        byte[] keyId,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        var subkeys = Subkeys.ToList();
        foreach (var subkey in subkeys)
        {
            if (Arrays.AreEqual(subkey.KeyId, keyId))
            {
                var index = subkeys.IndexOf(subkey);
                subkeys[index] = subkey.RevokeBy(this, revocationReason, reasonTag, time);
            }
        }
        return new PrivateKey(
            SecretKeyPacket,
            RevocationSignatures,
            DirectSignatures,
            Users,
            subkeys.ToArray()
        );
    }
}