// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Type;

/// <summary>
///     User attribute sub-packet class
/// </summary>
public class UserAttributeSubPacket(int type, byte[] data) : ISubPacket
{
    public int Type => type;

    public byte[] Data => data;

    public byte[] ToBytes()
    {
        return
        [
            ..BasePacket.SimpleLength(data.Length),
            (byte)type,
            ..data
        ];
    }
}