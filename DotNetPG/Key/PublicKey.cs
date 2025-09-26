// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Type;

/// <summary>
/// OpenPGP public key class.
/// </summary>
public class PublicKey : BaseKey, IPublicKey
{
    private readonly IPublicKeyPacket _publicKeyPacket;

    public PublicKey(IPacketList packetList) : base(packetList)
    {
        if (KeyPacket is IPublicKeyPacket keyPacket)
        {
            _publicKeyPacket = keyPacket;
        }
        else
        {
            throw new Exception("Key packet is not a public key.");
        }
    }

    public string Armor() => Common.Armor.Encode(ArmorType.PublicKey, PacketList.Encode(), []);

    public IPublicKeyPacket PublicKeyPacket => _publicKeyPacket;
}