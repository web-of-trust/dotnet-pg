// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Symmetric key encrypted session key interface.
/// </summary>
public interface ISymmetricKeyEncryptedSessionKey : IEncryptedSessionKey
{
    /// <summary>
    ///     Decrypt session key
    /// </summary>
    IEncryptedSessionKey Decrypt(string password);
}