// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Type;

/// <summary>
///     Implementation an OpenPGP sub public key packet (Tag 14).
/// </summary>
public class PublicSubkey : PublicKey, ISubkeyPacket
{
    public PublicSubkey(
        int version,
        DateTime creationTime,
        KeyAlgorithm keyAlgorithm,
        IKeyMaterial keyMaterial
    ) : base(version, creationTime, keyAlgorithm, keyMaterial)
    {
        Type = PacketType.PublicSubkey;
    }

    /// <summary>
    ///     Read public sub-key from bytes
    /// </summary>
    public new static PublicSubkey FromBytes(byte[] bytes)
    {
        var record = DecodePublicKey(bytes);
        return new PublicSubkey(
            record.Version,
            record.CreationTime,
            record.KeyAlgorithm,
            record.KeyMaterial
        );
    }
}