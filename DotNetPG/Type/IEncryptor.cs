// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
/// Encryptor interface
/// </summary>
public interface IEncryptor
{
    /// <summary>
    /// Encrypt a message
    /// </summary>
    IEncryptedMessage Encrypt(ILiteralMessage message, DateTime? time = null);
}
