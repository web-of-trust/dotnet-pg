// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Org.BouncyCastle.Security;

/// <summary>
///     Implementation of the Padding packet (Tag 21)
/// </summary>
public class Padding : BasePacket
{
    private const int PaddingMin = 16;
    private const int PaddingMax = 32;

    private readonly byte[] _padding;

    public Padding(byte[] padding)
        : base(PacketType.Padding)
    {
        var length = Math.Min(
            Math.Max(padding.Length, PaddingMin), PaddingMax
        );
        _padding = padding.Take(length).ToArray();
    }

    /// <summary>
    ///     Create random padding.
    /// </summary>
    /// <param name="length">The length of padding to be generated.</param>
    public static Padding CreatePadding(int length)
    {
        return new Padding(SecureRandom.GetNextBytes(
            new SecureRandom(),
            Math.Min(Math.Max(length, PaddingMin), PaddingMax)
        ));
    }

    public override byte[] ToBytes()
    {
        return _padding;
    }
}