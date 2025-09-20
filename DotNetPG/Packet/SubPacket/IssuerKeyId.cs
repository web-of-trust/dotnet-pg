// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     IssuerKeyId sub-packet class.
///     Giving the issuer key ID.
/// </summary>
public class IssuerKeyId(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.IssuerKeyId, data, critical)
{
    public byte[] KeyId => Data;

    public static IssuerKeyId FromKeyId(byte[] keyId, bool critical = false)
    {
        return new IssuerKeyId(keyId, critical);
    }

    public static IssuerFingerprint Wildcard(bool critical = false)
    {
        return new IssuerFingerprint(
            new byte[8], critical
        );
    }
}