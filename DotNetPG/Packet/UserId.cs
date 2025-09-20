// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Type;
using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
///     Implementation of the User ID packet (Tag 13)
/// </summary>
public class UserId : BasePacket, IUserIdPacket
{
    public UserId(string id) : base(PacketType.UserId)
    {
        Id = id;
        Name = ExtractName();
        Email = ExtractEmail();
        Comment = ExtractComment();
    }

    public string Id { get; }

    public string Name { get; }

    public string Email { get; }

    public string Comment { get; }

    public override byte[] ToBytes()
    {
        return Encoding.UTF8.GetBytes(Id);
    }

    public byte[] SignBytes()
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, Id.Length);
        return [0xb4, ..bytes, ..ToBytes()];
    }

    /// <summary>
    ///     Read User ID packet key from bytes
    /// </summary>
    public static UserId FromBytes(byte[] bytes)
    {
        return new UserId(Encoding.UTF8.GetString(bytes));
    }

    private string ExtractName()
    {
        IList<char> charArray = [];
        var chars = Id.ToCharArray();
        foreach (var chr in chars)
        {
            if (chr == '(' || chr == '<') break;

            charArray.Add(chr);
        }

        return new string(charArray.ToArray()).Trim();
    }

    private string ExtractEmail()
    {
        var match = Regex.Match(
            Id,
            @"\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b",
            RegexOptions.IgnoreCase
        );
        return match.Success ? match.Value : string.Empty;
    }

    private string ExtractComment()
    {
        if (Id.Contains('(') && Id.Contains(')'))
        {
            var start = Id.IndexOf('(') + 1;
            var length = Id.IndexOf(')') - start;
            return Id.Substring(start, length);
        }

        return string.Empty;
    }
}