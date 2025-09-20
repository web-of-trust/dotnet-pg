// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     KeyFlags sub-packet class.
///     Holding the key flag values.
/// </summary>
public class KeyFlags(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.KeyFlags, data, critical)
{
    public int Flags
    {
        get
        {
            var flags = 0;
            for (var i = 0; i < Data.Length; i++)
            {
                flags |= Data[i] << (i * 8);
                ;
            }

            return flags;
        }
    }

    public bool IsCertifyKeys => (Flags & (int)KeyFlag.CertifyKeys) == (int)KeyFlag.CertifyKeys;

    public bool IsSignData => (Flags & (int)KeyFlag.SignData) == (int)KeyFlag.SignData;

    public bool IsEncryptCommunication =>
        (Flags & (int)KeyFlag.EncryptCommunication) == (int)KeyFlag.EncryptCommunication;

    public bool IsEncryptStorage => (Flags & (int)KeyFlag.EncryptStorage) == (int)KeyFlag.EncryptStorage;

    public static KeyFlags FromFlags(int flags, bool critical = false)
    {
        return new KeyFlags(FlagsToBytes(flags), critical);
    }

    private static byte[] FlagsToBytes(int flags)
    {
        var size = 0;
        var bytes = new List<byte>();
        for (var i = 0; i < 4; i++)
        {
            bytes.Add((byte)(flags >> (i * 8)));
            if (bytes[i] != 0) size = i;
        }

        return bytes.Take(size + 1).ToArray();
    }
}