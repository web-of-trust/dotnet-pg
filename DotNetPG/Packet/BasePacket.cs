// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Type;

/// <summary>
///     Abstract packet class
/// </summary>
public abstract class BasePacket(PacketType type) : IPacket
{
    private const int PartialMinSize = 512;
    private const int PartialMaxSize = 1024;
    private const double Ln2 = 0.69314718055994530942;

    /// <summary>
    ///     Get encode tag byte
    /// </summary>
    protected byte TypeByte => (byte)((int)Type | 0xc0);

    /// <summary>
    ///     Get packet type
    /// </summary>
    public PacketType Type { get; protected set; } = type;

    public abstract byte[] ToBytes();

    public byte[] Encode()
    {
        return Type switch
        {
            PacketType.AeadEncryptedData or
                PacketType.CompressedData or
                PacketType.LiteralData or
                PacketType.SymEncryptedData or
                PacketType.SymEncryptedIntegrityProtectedData => PartialEncode(),
            _ => SimpleEncode()
        };
    }

    public static byte[] SimpleLength(int length)
    {
        return length switch
        {
            < 192 => [(byte)length],
            < 8384 =>
            [
                (byte)((((length - 192) >> 8) & 0xff) + 192),
                (byte)((length - 192) & 0xff)
            ],
            _ => [0xff, ..Helper.Pack32(length)]
        };
    }

    private byte[] SimpleEncode()
    {
        var bytes = ToBytes();
        return
        [
            TypeByte,
            ..SimpleLength(bytes.Length),
            ..bytes
        ];
    }

    private byte[] PartialEncode()
    {
        var data = ToBytes();
        var dataLen = data.Length;
        var partialData = new List<byte>([TypeByte]);
        while (dataLen >= PartialMinSize)
        {
            var maxSize = Math.Min(PartialMaxSize, dataLen);
            var powerOf2 = Math.Min((int)(Math.Log(maxSize) / Ln2), 30);
            var chunkSize = 1 << powerOf2;

            partialData.AddRange([
                (byte)(224 + powerOf2),
                ..data.Take(chunkSize)
            ]);
            data = data.Skip(chunkSize).ToArray();
            dataLen = data.Length;
        }

        partialData.AddRange([..SimpleLength(dataLen), ..data]);

        return partialData.ToArray();
    }
}