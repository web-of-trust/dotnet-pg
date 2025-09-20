// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     Exportable certification sub-packet class
/// </summary>
public class ExportableCertification(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.ExportableCertification, data, critical)
{
    public static ExportableCertification FromExportable(
        bool exportable = true, bool critical = false
    )
    {
        return new ExportableCertification(
            [(byte)(exportable ? 0x01 : 0x00)], critical
        );
    }
}