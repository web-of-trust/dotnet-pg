// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using System.Buffers.Binary;

/// <summary>
///     Packet reader class
/// </summary>
public sealed class PacketReader(PacketType type, byte[] data, int length)
{
    /// <summary>
    ///     Get packet type
    /// </summary>
    public PacketType Type => type;

    /// <summary>
    ///     Get packet data
    /// </summary>
    public byte[] Data => data;

    /// <summary>
    ///     Get packet length
    /// </summary>
    public int Length => length;

    /// <summary>
    ///     Read packet from bytes
    /// </summary>
    public static PacketReader Read(byte[] bytes)
    {
        var offset = 0;
        if (bytes.Length < 2 || (bytes[offset] & 0x80) == 0)
            throw new InvalidDataException(
                "Data probably does not conform to a valid OpenPGP format."
            );

        var header = bytes[offset++];
        var isOld = (header & 0x40) == 0;
        var typeByte = isOld ? (header & 0x3f) >> 2 : header & 0x3f;
        var type = (PacketType)typeByte;

        byte[] data;
        int dataLength;
        if (isOld)
        {
            switch (header & 0x03)
            {
                case 0:
                    dataLength = bytes[offset++];
                    break;
                case 1:
                    dataLength = BinaryPrimitives.ReadInt16BigEndian(
                        bytes.Skip(offset).Take(2).ToArray()
                    );
                    offset += 2;
                    break;
                case 2:
                    dataLength = BinaryPrimitives.ReadInt32BigEndian(
                        bytes.Skip(offset).Take(4).ToArray()
                    );
                    offset += 4;
                    break;
                default:
                    dataLength = bytes.Length - offset;
                    break;
            }

            data = bytes.Skip(offset).Take(dataLength).ToArray();
        }
        else
        {
            dataLength = bytes[offset++];
            if (dataLength < 192)
            {
                data = bytes.Skip(offset).Take(dataLength).ToArray();
            }
            else if (dataLength < 224)
            {
                dataLength = ((dataLength - 192) << 8) + bytes[offset++] + 192;
                data = bytes.Skip(offset).Take(dataLength).ToArray();
            }
            else if (dataLength < 255)
            {
                var partialLen = 1 << (dataLength & 0x1f);
                var partialData = new List<byte>(bytes.Skip(offset).Take(partialLen));
                var partialPos = offset + partialLen;
                while (true)
                {
                    partialLen = bytes[partialPos++];
                    if (partialLen < 192)
                    {
                        partialData.AddRange(
                            bytes.Skip(partialPos).Take(partialLen)
                        );
                        partialPos += partialLen;
                        break;
                    }

                    if (partialLen < 224)
                    {
                        partialLen = ((partialLen - 192) << 8) + bytes[partialPos++] + 192;
                        partialData.AddRange(
                            bytes.Skip(partialPos).Take(partialLen)
                        );
                        partialPos += partialLen;
                        break;
                    }

                    if (partialLen < 255)
                    {
                        partialLen = 1 << (partialLen & 0x1f);
                        partialData.AddRange(
                            bytes.Skip(partialPos).Take(partialLen)
                        );
                        partialPos += partialLen;
                    }
                    else
                    {
                        partialLen = BinaryPrimitives.ReadInt32BigEndian(
                            bytes.Take(4).ToArray()
                        );
                        partialPos += 4;
                        partialData.AddRange(
                            bytes.Skip(partialPos).Take(partialLen)
                        );
                        partialPos += partialLen;
                        break;
                    }
                }

                data = partialData.ToArray();
                dataLength = partialPos - offset;
            }
            else
            {
                dataLength = BinaryPrimitives.ReadInt32BigEndian(
                    bytes.Take(4).ToArray()
                );
                offset += 4;
                data = bytes.Skip(offset).Take(dataLength).ToArray();
            }
        }

        return new PacketReader(type, data, offset + dataLength);
    }
}