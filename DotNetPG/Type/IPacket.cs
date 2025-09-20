// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Packet interface
/// </summary>
public interface IPacket
{
    /// <summary>
    ///     Get packet type
    /// </summary>
    PacketType Type { get; }

    /// <summary>
    ///     Encode packet to bytes
    /// </summary>
    byte[] Encode();

    /// <summary>
    ///     Serialize packet to bytes
    /// </summary>
    byte[] ToBytes();
}