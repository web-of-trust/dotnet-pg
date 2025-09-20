// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     PreferredAeadAlgorithms sub-packet class
/// </summary>
public class PreferredAeadAlgorithms(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.PreferredAeadAlgorithms, data, critical)
{
    public AeadAlgorithm[] Preferences => Data.Select(pref => (AeadAlgorithm)pref).ToArray();
}