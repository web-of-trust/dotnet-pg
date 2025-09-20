// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Session key cryptor interface.
/// </summary>
public interface ISessionKeyCrypto
{
    /// <summary>
    ///     Decrypt session key by using secret key packet
    /// </summary>
    byte[] Decrypt(ISecretKeyPacket secretKey);

    /// <summary>
    ///     Serialize session key crypto to bytes
    /// </summary>
    byte[] ToBytes();
}