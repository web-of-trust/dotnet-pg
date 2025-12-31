// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Public key encrypted session key interface
/// </summary>
public interface IPublicKeyEncryptedSessionKey : IEncryptedSessionKey, IPacket
{
    int Version { get; }
    
    int KeyVersion { get; }
    
    byte[] KeyFingerprint { get; }
    
    byte[] KeyId { get; }

    KeyAlgorithm KeyAlgorithm { get; }
    
    ISessionKeyCrypto SessionKeyCrypto { get; }

    /// <summary>
    ///     Decrypt session key
    /// </summary>
    IEncryptedSessionKey Decrypt(ISecretKeyPacket secretKey);
}
