// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Public key interface.
/// </summary>
public interface IPublicKey : IKey
{
    /// <summary>
    ///     Get public key packet.
    /// </summary>
    IPublicKeyPacket PublicKeyPacket { get; }
}