// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;
using Type;

/// <summary>
///     IntendedRecipientFingerprint sub-packet class.
///     Giving the intended recipient fingerprint.
/// </summary>
public class IntendedRecipientFingerprint(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.IntendedRecipientFingerprint, data, critical)
{
    public int KeyVersion => Data[0];

    public byte[] KeyFingerprint => Data.Skip(1).ToArray();

    public static IntendedRecipientFingerprint FromKeyPacket(IKeyPacket key, bool critical = false)
    {
        return new IntendedRecipientFingerprint(
            [(byte)key.Version, ..key.Fingerprint], critical
        );
    }

    public static IntendedRecipientFingerprint Wildcard(bool isV6 = true, bool critical = false)
    {
        return new IntendedRecipientFingerprint(
            isV6 ? new byte[32] : new byte[20], critical
        );
    }
}