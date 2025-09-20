// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;
using Type;
using System.Text;

/// <summary>
///     NotationData sub-packet class.
///     Class provided a NotationData object according to RFC 9580, section 5.2.3.24.
/// </summary>
public class NotationData(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.NotationData, data, critical), INotationData
{
    private const int FlagLength = 4;
    private const int NameLength = 2;
    private const int ValueLength = 2;

    public const string SaltNotaion = "salt@dotpg.openpgp.org";

    public byte[] NameData
    {
        get
        {
            var length = ((Data[FlagLength] & 0xff) << 8) + (Data[FlagLength + 1] & 0xff);
            var offset = FlagLength + NameLength + ValueLength;
            return Data.Skip(offset).Take(length).ToArray();
        }
    }

    public byte[] ValueData
    {
        get
        {
            var nameLength = ((Data[FlagLength] & 0xff) << 8) + (Data[FlagLength + 1] & 0xff);
            var length = ((Data[FlagLength + NameLength] & 0xff) << 8) + (Data[FlagLength + NameLength + 1] & 0xff);
            var offset = FlagLength + NameLength + ValueLength + nameLength;
            return Data.Skip(offset).Take(length).ToArray();
        }
    }

    public bool IsHumanReadable => Data[0] == 0x80;

    public string NotationName => Encoding.UTF8.GetString(NameData);

    public string NotationValue => Encoding.UTF8.GetString(ValueData);

    public static NotationData FromNotation(
        string name, string value, bool humanReadable = false, bool critical = false
    )
    {
        return new NotationData(NotationToBytes(name, value, humanReadable), critical);
    }

    private static byte[] NotationToBytes(
        string name, string value, bool humanReadable = false
    )
    {
        var nameData = Encoding.UTF8.GetBytes(name);
        var nameLength = Math.Min(nameData.Length, 0xffff);
        if (nameLength != nameData.Length) throw new ArgumentException("Notation name exceeds maximum length.");

        var valueData = Encoding.UTF8.GetBytes(value);
        var valueLength = Math.Min(valueData.Length, 0xffff);
        if (valueLength != valueData.Length) throw new ArgumentException("Notation value exceeds maximum length.");
        return
        [
            ..humanReadable ? [0x80] : new byte[4],
            (byte)(nameLength >> 8),
            (byte)(nameLength >> 0),
            (byte)(valueLength >> 8),
            (byte)(valueLength >> 0),
            ..nameData.Take(nameLength).ToArray(),
            ..valueData.Take(valueLength).ToArray()
        ];
    }
}