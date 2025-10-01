// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
using Type;

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
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] directSignatures,
        IUser[] users,
        ISubkey[] subkeys
    ) : base(keyPacket, revocationSignatures, directSignatures, users, subkeys)
    {
        SecretKeyPacket = keyPacket;
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

            return new PublicKey(new PacketList(packets.ToArray()));
        }
    }

    public string Armor() => Common.Armor.Encode(ArmorType.PrivateKey, PacketList.Encode(), []);

    public override IKey CertifyBy(IPrivateKey signKey, DateTime? time = null)
    {
        var primaryUser = PrimaryUser;
        if (primaryUser == null) return this;

        var certifedUser = primaryUser.CertifyBy(signKey, time);
        var certifedUserId = certifedUser.UserId;

        IList<IUser> users = [certifedUser];
        foreach (var user in Users)
        {
            if (user.UserId != certifedUserId)
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

    public IPrivateKey Encrypt(string passphrase, string[]? subkeyPassphrases = null,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256)
    {
        throw new NotImplementedException();
    }

    public IPrivateKey Decrypt(string passphrase, string[]? subkeyPassphrases = null)
    {
        throw new NotImplementedException();
    }

    public IPrivateKey AddUsers(string[] userIds)
    {
        throw new NotImplementedException();
    }

    public IPrivateKey AddSubkey(string passphrase, KeyAlgorithm keyAlgorithm = KeyAlgorithm.RsaGeneral,
        RsaKeySize rsaKeySize = RsaKeySize.Normal, EcCurve ecCurve = EcCurve.Secp521R1, int keyExpiry = 0,
        bool forSigning = false, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey CertifyKey(IKey key, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey RevokeKey(IKey key, string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey RevokeUser(string userId, string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey RevokeSubkey(byte[] keyId, string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason, DateTime? time = null)
    {
        throw new NotImplementedException();
    }
}