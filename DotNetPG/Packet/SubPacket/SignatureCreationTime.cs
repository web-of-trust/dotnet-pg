// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Common;
using Enum;
using System.Buffers.Binary;

/// <summary>
///     SignatureCreationTime sub-packet class
/// </summary>
public class SignatureCreationTime(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.SignatureCreationTime, data, critical)
{
    public DateTime CreationTime => DateTimeOffset.FromUnixTimeSeconds(
        BinaryPrimitives.ReadInt32BigEndian(Data)
    ).LocalDateTime;

    public static SignatureCreationTime FromTime(DateTime time, bool critical = false)
    {
        var dto = new DateTimeOffset(time);
        return new SignatureCreationTime(
            Helper.Pack32((int)dto.ToUnixTimeSeconds()),
            critical
        );
    }
}