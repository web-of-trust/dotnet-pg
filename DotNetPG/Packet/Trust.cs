// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;

/// <summary>
///     Implementation of the Trust packet (Tag 12)
/// </summary>
public class Trust(byte[] data) : BasePacket(PacketType.Trust)
{
    /// <summary>
    ///     Read Trust Packet key from bytes
    /// </summary>
    public static Trust FromBytes(byte[] bytes)
    {
        return new Trust(bytes);
    }

    public override byte[] ToBytes()
    {
        return data;
    }
}