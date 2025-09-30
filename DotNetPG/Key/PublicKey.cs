// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
using Type;

/// <summary>
/// OpenPGP public key class.
/// </summary>
public class PublicKey : BaseKey, IPublicKey
{
    public PublicKey(IPacketList packetList) : base(packetList)
    {
        if (KeyPacket is IPublicKeyPacket keyPacket)
        {
            PublicKeyPacket = keyPacket;
        }
        else
        {
            throw new Exception("Key packet is not a public key.");
        }
    }

    public PublicKey(
        IPublicKeyPacket keyPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] directSignatures,
        IUser[] users,
        ISubkey[] subkeys
    ) : base(keyPacket, revocationSignatures, directSignatures, users, subkeys)
    {
        PublicKeyPacket = keyPacket;
    }

    public static PublicKey FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static PublicKey FromBytes(byte[] bytes)
    {
        return new PublicKey(Packet.PacketList.Decode(bytes));
    }

    public string Armor() => Common.Armor.Encode(ArmorType.PublicKey, PacketList.Encode(), []);

    public IPublicKeyPacket PublicKeyPacket { get; }

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
        return new PublicKey(
            PublicKeyPacket,
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
        return new PublicKey(
            PublicKeyPacket,
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
}