// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Type;

/// <summary>
///     Signature sub-packet class
/// </summary>
public class SignatureSubPacket(int type, byte[] data, bool critical = false) : ISubPacket
{
    public int Type => type;

    public byte[] Data => data;

    public byte[] ToBytes()
    {
        return
        [
            ..BasePacket.SimpleLength(data.Length + 1),
            critical ? (byte)(type | 0x80) : (byte)type,
            ..data
        ];
    }
}