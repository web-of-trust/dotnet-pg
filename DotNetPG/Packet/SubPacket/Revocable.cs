// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     Revocable sub-packet class
/// </summary>
public class Revocable(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.Revocable, data, critical);