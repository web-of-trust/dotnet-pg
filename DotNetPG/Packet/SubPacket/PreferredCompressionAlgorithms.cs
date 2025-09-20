// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     PreferredCompressionAlgorithms sub-packet class
/// </summary>
public class PreferredCompressionAlgorithms(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.PreferredCompressionAlgorithms, data, critical)
{
    public CompressionAlgorithm[] Preferences => Data.Select(pref => (CompressionAlgorithm)pref).ToArray();
}