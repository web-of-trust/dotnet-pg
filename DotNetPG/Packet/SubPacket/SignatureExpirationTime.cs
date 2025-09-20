// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Common;
using Enum;
using System.Buffers.Binary;

/// <summary>
///     SignatureExpirationTime sub-packet class.
///     Giving signature expiration time.
/// </summary>
public class SignatureExpirationTime(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.SignatureExpirationTime, data, critical)
{
    public DateTime ExpirationTime => DateTimeOffset.FromUnixTimeSeconds(
        BinaryPrimitives.ReadInt32BigEndian(Data)
    ).LocalDateTime;

    public static SignatureExpirationTime FromTime(DateTime time, bool critical = false)
    {
        var dto = new DateTimeOffset(time);
        return new SignatureExpirationTime(
            Helper.Pack32((int)dto.ToUnixTimeSeconds()),
            critical
        );
    }
}