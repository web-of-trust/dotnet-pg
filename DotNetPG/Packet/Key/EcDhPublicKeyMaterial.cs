// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

/// <summary>
///     ECDH public key material
/// </summary>
public class EcDhPublicKeyMaterial(
    DerObjectIdentifier oid,
    BigInteger point,
    HashAlgorithm kdfHash,
    SymmetricAlgorithm kdfSymmetric,
    int reserved = 0)
    : EcPublicKeyMaterial(oid, point)
{
    public HashAlgorithm KdfHash => kdfHash;

    public SymmetricAlgorithm KdfSymmetric => kdfSymmetric;

    public int Reserved => reserved;

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EcDhPublicKeyMaterial FromBytes(byte[] bytes)
    {
        var offset = 0;
        var length = bytes[offset++];
        byte[] data =
        [
            0x06, length, ..bytes.Skip(offset).Take(length).ToArray()
        ];
        var oid = DerObjectIdentifier.GetInstance(data);
        offset += length;
        var point = Helper.ReadMpi(bytes.Skip(offset).ToArray());

        offset += ((point.BitLength + 7) >> 3) + 2;
        var kdfBytes = bytes.Skip(offset).ToArray();
        return new EcDhPublicKeyMaterial(
            oid,
            point,
            (HashAlgorithm)kdfBytes[2],
            (SymmetricAlgorithm)kdfBytes[3],
            kdfBytes[1]
        );
    }

    public override byte[] ToBytes()
    {
        return
        [
            ..base.ToBytes(),
            0x03, (byte)reserved, (byte)kdfHash, (byte)kdfSymmetric
        ];
    }
}