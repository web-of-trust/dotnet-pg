// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Packet list interface
/// </summary>
public interface IPacketList
{
    /// <summary>
    ///     Get packets
    /// </summary>
    IReadOnlyList<IPacket> Packets { get; }

    IPacket this[int index] { get; }

    /// <summary>
    ///     Encode packets to bytes
    /// </summary>
    byte[] Encode();
}