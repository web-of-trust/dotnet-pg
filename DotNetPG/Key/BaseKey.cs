// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using DotNetPG.Type;

namespace DotNetPG.Key;

/// <summary>
///     Abstract OpenPGP key class
/// </summary>
public abstract class BaseKey
{
    private readonly IKeyPacket _keyPacket;

    private readonly IReadOnlyList<ISignaturePacket> _revocationSignatures;

    private readonly IReadOnlyList<ISignaturePacket> _directSignatures;

    private readonly IReadOnlyList<IUser> _users;

    private readonly IReadOnlyList<ISubkey> _subkey;

    public BaseKey(IPacketList packetList)
    {
        
    }

    private void ReadPacketList(IPacketList packetList)
    {
        var keyPackets = packetList.Packets.TakeWhile(packet => packet is IKeyPacket).ToList();
        if (keyPackets.Count == 0)
        {
            throw new Exception("Key packet not found in packet list.");
        }

        if (keyPackets.Count > 1)
        {
            throw new Exception("Key block contains multiple key packets.");
        }

        var keyPacket = keyPackets.OfType<IKeyPacket>().First();
        var remainPackets = packetList.Packets.SkipWhile(packet => packet is IKeyPacket).ToList();

        var revocationSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).OfType<ISignaturePacket>().ToList();

        remainPackets = remainPackets.SkipWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).ToList();
    }
}
