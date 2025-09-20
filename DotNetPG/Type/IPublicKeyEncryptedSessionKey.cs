// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Public key encrypted session key interface
/// </summary>
public interface IPublicKeyEncryptedSessionKey : IEncryptedSessionKey
{
    /// <summary>
    ///     Decrypt session key
    /// </summary>
    IEncryptedSessionKey Decrypt(ISecretKeyPacket secretKey);
}