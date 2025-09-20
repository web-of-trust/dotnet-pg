// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     TrustSignature sub-packet class
/// </summary>
public class TrustSignature(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.TrustSignature, data, critical)
{
    public int TrustLevel => Data[0];

    public int TrustAmount => Data[1];
}