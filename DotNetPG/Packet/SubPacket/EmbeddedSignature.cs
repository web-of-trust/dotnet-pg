// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;
using Type;

/// <summary>
///     EmbeddedSignature sub-packet class
/// </summary>
public class EmbeddedSignature(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.EmbeddedSignature, data, critical)
{
    public ISignaturePacket Signature => SignaturePacket.FromBytes(Data);

    public static EmbeddedSignature FromSignature(
        ISignaturePacket signature, bool critical = false
    )
    {
        return new EmbeddedSignature(signature.ToBytes(), critical);
    }
}