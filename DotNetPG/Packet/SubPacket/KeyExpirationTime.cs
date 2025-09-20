// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Common;
using Enum;
using System.Buffers.Binary;

/// <summary>
///     KeyExpirationTime sub-packet class.
///     Giving time after creation at which the key expires.
/// </summary>
public class KeyExpirationTime(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.KeyExpirationTime, data, critical)
{
    public int ExpirationTime => BinaryPrimitives.ReadInt32BigEndian(Data);

    public static KeyExpirationTime FromTime(int seconds, bool critical = false)
    {
        return new KeyExpirationTime(
            Helper.Pack32(seconds),
            critical
        );
    }
}