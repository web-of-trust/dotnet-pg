// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Type;
using System.Buffers.Binary;
using System.Text;

/// <summary>
///     Implementation of the Literal Data packet (Tag 11).
///     A Literal Data packet contains the body of a message; data that is not to be further interpreted.
/// </summary>
public class LiteralData(byte[] data, LiteralFormat format, string filename = "", DateTime? time = null)
    : BasePacket(PacketType.LiteralData), ILiteralData
{
    public string Text => Encoding.ASCII.GetString(data);
    public LiteralFormat Format => format;

    public string Filename => filename;

    public DateTime Time => time ?? DateTime.Now;

    public byte[] Data => data;

    public byte[] Header =>
    [
        (byte)format,
        (byte)filename.Length,
        ..Encoding.UTF8.GetBytes(filename),
        ..Helper.Pack32(
            (int)new DateTimeOffset(Time).ToUnixTimeSeconds()
        )
    ];

    public byte[] SignBytes()
    {
        if (format != LiteralFormat.Text && format != LiteralFormat.Utf8) return data;
        var text = Helper.RemoveTrailingSpaces(
            Encoding.UTF8.GetString(data)
        );
        return Encoding.UTF8.GetBytes(text);
    }

    /// <summary>
    ///     Read Literal Data packet from bytes
    /// </summary>
    public static LiteralData FromBytes(byte[] bytes)
    {
        var offset = 0;
        var format = (LiteralFormat)bytes[offset++];
        var length = bytes[offset++];
        var filename = Encoding.UTF8.GetString(bytes, offset, length);
        offset += length;

        var time = DateTimeOffset.FromUnixTimeSeconds(
            BinaryPrimitives.ReadInt32BigEndian(
                bytes.Skip(offset).Take(4).ToArray()
            )
        ).LocalDateTime;
        offset += 4;
        var data = bytes.Skip(offset).ToArray();
        return new LiteralData(data, format, filename, time);
    }

    /// <summary>
    ///     Build Literal Data packet from text
    /// </summary>
    public static LiteralData FromText(
        string text,
        LiteralFormat format = LiteralFormat.Utf8,
        DateTime? time = null
    )
    {
        return new LiteralData(
            Encoding.UTF8.GetBytes(text), format, "", time
        );
    }

    public override byte[] ToBytes()
    {
        return [..Header, ..SignBytes()];
    }
}