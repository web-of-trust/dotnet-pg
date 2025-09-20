// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     Features sub-packet class
/// </summary>
public class Features(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.Features, data, critical)
{
    public bool SupportV1Seipd => (Data[0] & (int)SupportFeature.Version1Seipd) == (int)SupportFeature.Version1Seipd;

    public bool SupportAead => (Data[0] & (int)SupportFeature.AeadEncrypted) == (int)SupportFeature.AeadEncrypted;

    public bool SupportV2Seipd => (Data[0] & (int)SupportFeature.Version2Seipd) == (int)SupportFeature.Version2Seipd;

    public static Features FromFeatures(int features, bool critical = false)
    {
        return new Features([(byte)features], critical);
    }
}