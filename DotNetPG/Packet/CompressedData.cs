// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Type;
using System.IO.Compression;
using Org.BouncyCastle.Utilities.Bzip2;

/// <summary>
///     Implementation of the Compressed Data packet (Tag 8)
/// </summary>
public class CompressedData(
    byte[] compressed,
    IPacketList packetList,
    CompressionAlgorithm algorithm)
    : BasePacket(PacketType.CompressedData)
{
    public byte[] Compressed => compressed;

    public IPacketList PacketList { get; } = packetList;

    public CompressionAlgorithm Algorithm => algorithm;

    /// <summary>
    ///     Read Compressed Data packet from bytes
    /// </summary>
    public static CompressedData FromBytes(byte[] bytes)
    {
        var algorithm = (CompressionAlgorithm)bytes[0];
        var compressed = bytes.Skip(1).ToArray();
        return new CompressedData(
            compressed,
            Decompress(compressed, algorithm),
            algorithm
        );
    }

    /// <summary>
    ///     Build compressed data packet from packet list
    /// </summary>
    public static CompressedData FromPacketList(
        IPacketList packetList,
        CompressionAlgorithm algorithm = CompressionAlgorithm.Uncompressed
    )
    {
        var compressed = Compress(packetList, algorithm);
        return new CompressedData(
            compressed, packetList, algorithm
        );
    }

    public override byte[] ToBytes()
    {
        return [(byte)algorithm, ..compressed];
    }

    private static byte[] Compress(
        IPacketList packetList, CompressionAlgorithm algorithm
    )
    {
        switch (algorithm)
        {
            case CompressionAlgorithm.Zip:
                using (var output = new MemoryStream())
                {
                    using (var compressor = new DeflateStream(output, CompressionLevel.Optimal))
                    {
                        compressor.Write(packetList.Encode());
                    }

                    return output.ToArray();
                }
            case CompressionAlgorithm.Zlib:
                using (var output = new MemoryStream())
                {
                    using (var compressor = new ZLibStream(output, CompressionLevel.Optimal))
                    {
                        compressor.Write(packetList.Encode());
                    }

                    return output.ToArray();
                }
            case CompressionAlgorithm.BZip2:
                using (var output = new MemoryStream())
                {
                    using (var compressor = new CBZip2OutputStream(output))
                    {
                        compressor.Write(packetList.Encode());
                    }

                    return output.ToArray();
                }
            default:
                return packetList.Encode();
        }
    }

    private static IPacketList Decompress(
        byte[] compressed, CompressionAlgorithm algorithm
    )
    {
        switch (algorithm)
        {
            case CompressionAlgorithm.Zip:
                using (var output = new MemoryStream())
                {
                    using (var decompressor =
                           new DeflateStream(new MemoryStream(compressed), CompressionMode.Decompress))
                    {
                        decompressor.CopyTo(output);
                    }

                    return Packet.PacketList.Decode(output.ToArray());
                }
            case CompressionAlgorithm.Zlib:
                using (var output = new MemoryStream())
                {
                    using (var decompressor = new ZLibStream(new MemoryStream(compressed), CompressionMode.Decompress))
                    {
                        decompressor.CopyTo(output);
                    }

                    return Packet.PacketList.Decode(output.ToArray());
                }
            case CompressionAlgorithm.BZip2:
                using (var output = new MemoryStream())
                {
                    using (var decompressor = new CBZip2InputStream(new MemoryStream(compressed)))
                    {
                        decompressor.CopyTo(output);
                    }

                    return Packet.PacketList.Decode(output.ToArray());
                }
            default:
                return Packet.PacketList.Decode(compressed);
        }
    }
}