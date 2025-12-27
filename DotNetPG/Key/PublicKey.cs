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

    private PublicKey(
        IPublicKeyPacket keyPacket,
        IList<ISignaturePacket> revocationSignatures,
        IList<ISignaturePacket> directSignatures,
        IList<IUser> users,
        IList<ISubkey>  subkeys
    ) : base(keyPacket, revocationSignatures, directSignatures, users, subkeys)
    {
        PublicKeyPacket = keyPacket;
    }

    public static IList<IPublicKey> ReadPublicKeys(string armored)
    {
        return ReadPublicKeys(Common.Armor.Decode(armored).Data);
    }

    public static IList<IPublicKey> ReadPublicKeys(byte[] bytes)
    {
        IList<IPublicKey> publicKeys = [];
        var packetList = Packet.PacketList.Decode(bytes);
        var indexes = packetList.IndexOfType([PacketType.PublicKey]);
        for (var i = 0; i < indexes.Length; i++)
        {
            if ((i + 1) < indexes.Length)
            {
                publicKeys.Add(new PublicKey(
                    new PacketList(packetList.Packets.Skip(indexes[i]).Take(indexes[i + 1]).ToList())
                ));
            }
            else
            {
                publicKeys.Add(new PublicKey(
                    new PacketList(packetList.Packets.Skip(indexes[i]).ToList())
                ));
            }
        }
        return publicKeys;
    }

    public static IPublicKey FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static IPublicKey FromBytes(byte[] bytes)
    {
        return new PublicKey(Packet.PacketList.Decode(bytes));
    }

    public static string ArmorPublicKeys(IList<IPublicKey> keys) => Common.Armor.Encode(
        ArmorType.PublicKey,
        keys.SelectMany(key => key.PacketList.Encode()).ToArray()
    );

    public string Armor() => Common.Armor.Encode(ArmorType.PublicKey, PacketList.Encode());

    public IPublicKeyPacket PublicKeyPacket { get; }

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
