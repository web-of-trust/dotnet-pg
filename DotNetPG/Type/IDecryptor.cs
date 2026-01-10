// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
/// Decryptor interface
/// </summary>
public interface IDecryptor
{
    /// <summary>
    /// Decrypt an encrypted message
    /// </summary>
    ILiteralMessage Decrypt(IEncryptedMessage message);

    /// <summary>
    /// Decrypt a armored encrypted string
    /// </summary>
    /// <param name="messageData"></param>
    /// <returns></returns>
    ILiteralMessage Decrypt(string messageData);
}
