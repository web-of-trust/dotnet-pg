// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     SignatureTarget sub-packet class
///     RFC 9580, Section 5.2.3.33.
/// </summary>
public class SignatureTarget(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.SignatureTarget, data, critical)
{
    public KeyAlgorithm KeyAlgorithm => (KeyAlgorithm)Data[0];

    public HashAlgorithm HashAlgorithm => (HashAlgorithm)Data[1];

    public byte[] HashData => Data.Skip(2).ToArray();

    public static SignatureTarget FromHashData(
        KeyAlgorithm keyAlgorithm, HashAlgorithm hashAlgorithm, byte[] hashData, bool critical = false
    )
    {
        return new SignatureTarget(
            HashDataToBytes(keyAlgorithm, hashAlgorithm, hashData), critical
        );
    }

    private static byte[] HashDataToBytes(
        KeyAlgorithm keyAlgorithm, HashAlgorithm hashAlgorithm, byte[] hashData
    )
    {
        return [(byte)keyAlgorithm, (byte)hashAlgorithm, ..hashData];
    }
}