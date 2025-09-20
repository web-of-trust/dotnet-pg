// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;
using Type;

/// <summary>
///     IssuerFingerprint sub-packet class.
///     Giving the issuer key fingerprint.
/// </summary>
public class IssuerFingerprint(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.IssuerFingerprint, data, critical)
{
    public int KeyVersion => Data[0];

    public byte[] KeyFingerprint => Data.Skip(1).ToArray();

    public static IssuerFingerprint FromKeyPacket(IKeyPacket key, bool critical = false)
    {
        return new IssuerFingerprint(
            [(byte)key.Version, ..key.Fingerprint], critical
        );
    }

    public static IssuerFingerprint Wildcard(bool isV6 = true, bool critical = false)
    {
        return new IssuerFingerprint(
            isV6 ? new byte[32] : new byte[20], critical
        );
    }
}