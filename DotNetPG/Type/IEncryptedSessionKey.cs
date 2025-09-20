// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Encrypted session key interface.
/// </summary>
public interface IEncryptedSessionKey
{
    /// <summary>
    ///     Get session key.
    /// </summary>
    ISessionKey? SessionKey { get; }
}