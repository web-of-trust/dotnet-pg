// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Sub-packet interface
/// </summary>
public interface ISubPacket
{
    /// <summary>
    ///     Get type
    /// </summary>
    int Type { get; }

    /// <summary>
    ///     Get data
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    ///     Serialize sub packet to bytes
    /// </summary>
    byte[] ToBytes();
}