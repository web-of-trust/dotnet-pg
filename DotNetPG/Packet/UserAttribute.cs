// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using Type;

/// <summary>
///     Implementation of the User Attribute packet (Tag 17)
/// </summary>
public class UserAttribute(UserAttributeSubPacket[] attributes)
    : BasePacket(PacketType.UserAttribute), IUserIdPacket
{
    public UserAttributeSubPacket[] Attributes => attributes;

    public override byte[] ToBytes()
    {
        return attributes.SelectMany(attr => attr.ToBytes()).ToArray();
    }

    public byte[] SignBytes()
    {
        var data = ToBytes();
        return
        [
            0xd1,
            ..Helper.Pack32(data.Length),
            ..data
        ];
    }

    /// <summary>
    ///     Read User Attribute packet key from bytes
    /// </summary>
    public static UserAttribute FromBytes(byte[] bytes)
    {
        return new UserAttribute(ReadSubPackets(bytes));
    }

    private static UserAttributeSubPacket[] ReadSubPackets(byte[] bytes)
    {
        var attributes = new List<UserAttributeSubPacket>();
        while (bytes.Length > 0)
        {
            var reader = SubPacketReader.Read(bytes);
            bytes = bytes.Skip(reader.Length).ToArray();
            if (reader.Type == ImageUserAttribute.Jpeg)
                attributes.Add(new ImageUserAttribute(reader.Data));
            else
                attributes.Add(
                    new UserAttributeSubPacket(reader.Type, reader.Data)
                );
        }

        return attributes.ToArray();
    }
}