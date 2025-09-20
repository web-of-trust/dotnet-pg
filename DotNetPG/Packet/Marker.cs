// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;

/// <summary>
///     Implementation of the strange "Marker packet" (Tag 10)
/// </summary>
public class Marker() : BasePacket(PacketType.Marker)
{
    public override byte[] ToBytes()
    {
        return "PGP"u8.ToArray();
    }
}