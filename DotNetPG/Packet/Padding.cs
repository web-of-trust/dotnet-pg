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
    public static Padding CreatePadding()
    {
        var random = new SecureRandom();
        return new Padding(SecureRandom.GetNextBytes(
            random, random.Next(PaddingMin, PaddingMax)
        ));
    }

    public override byte[] ToBytes()
    {
        return _padding;
    }
}