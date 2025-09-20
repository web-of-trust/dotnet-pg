// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Packet container interface.
/// </summary>
public interface IPacketContainer
{
    /// <summary>
    ///     Get packet list.
    /// </summary>
    IPacketList PacketList { get; }

    /// <summary>
    ///     Get contained packets.
    /// </summary>
    IList<IPacket> Packets { get; }
}