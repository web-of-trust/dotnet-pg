// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     RevocationKey sub-packet class
/// </summary>
public class RevocationKey(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.RevocationKey, data, critical)
{
    public RevocationKeyTag SignatureClass => (RevocationKeyTag)Data[0];

    public KeyAlgorithm KeyAlgorithm => (KeyAlgorithm)Data[1];

    public byte[] Fingerprint => Data.Skip(2).ToArray();

    public static RevocationKey FromRevocation(
        RevocationKeyTag signatureClass, KeyAlgorithm keyAlgorithm, byte[] fingerprint, bool critical = false
    )
    {
        return new RevocationKey(
            RevocationToBytes(signatureClass, keyAlgorithm, fingerprint), critical
        );
    }

    private static byte[] RevocationToBytes(
        RevocationKeyTag signatureClass, KeyAlgorithm keyAlgorithm, byte[] fingerprint
    )
    {
        return [(byte)signatureClass, (byte)keyAlgorithm, ..fingerprint];
    }
}