// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
/// Compressed Data packet interface
/// </summary>
public interface ICompressedData : IPacket
{
    /// <summary>
    /// Compressed data
    /// </summary>
    byte[] Compressed { get; }

    /// <summary>
    /// Get decompressed packet list contained within.
    /// </summary>
    IPacketList PacketList { get; }

    /// <summary>
    /// Compression algorithm
    /// </summary>
    CompressionAlgorithm Algorithm { get; }
}
