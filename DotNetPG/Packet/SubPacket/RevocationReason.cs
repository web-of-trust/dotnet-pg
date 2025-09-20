// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;
using System.Text;

/// <summary>
///     RevocationReason sub-packet class.
///     Represents revocation reason OpenPGP signature sub packet.
/// </summary>
public class RevocationReason(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.RevocationReason, data, critical)
{
    public RevocationReasonTag SignatureClass => (RevocationReasonTag)Data[0];

    public string Description => Encoding.UTF8.GetString(Data.Skip(1).ToArray());

    public static RevocationReason FromRevocation(
        RevocationReasonTag reason, string description, bool critical = false
    )
    {
        return new RevocationReason(
            RevocationToBytes(reason, description), critical
        );
    }

    public static byte[] RevocationToBytes(RevocationReasonTag reason, string description)
    {
        return [(byte)reason, ..Encoding.UTF8.GetBytes(description)];
    }
}