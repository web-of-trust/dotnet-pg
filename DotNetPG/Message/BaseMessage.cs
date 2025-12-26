// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Enum;
using Type;

/// <summary>
/// OpenPGP abstract message class
/// </summary>
public abstract class BaseMessage(IPacketList packetList) : IArmorable, IPacketContainer
{
    public IPacketList PacketList => packetList;

    public string Armor() => Common.Armor.Encode(ArmorType.Message, PacketList.Encode());
}
