// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
/// Encryptor interface
/// </summary>
public interface IEncryptor
{
    /// <summary>
    /// Encrypt a literal message
    /// </summary>
    IEncryptedMessage Encrypt(ILiteralMessage message, DateTime? time = null);

    /// <summary>
    /// Encrypt literal data
    /// </summary>
    IEncryptedMessage Encrypt(byte[] literalData, DateTime? time = null);

    /// <summary>
    /// Encrypt clear text
    /// </summary>
    IEncryptedMessage Encrypt(string text, DateTime? time = null);

    /// <summary>
    /// Bulk encrypt literal messages
    /// </summary>
    IList<IEncryptedMessage> BulkEncrypt(
        IList<ILiteralMessage> messages,
        ISessionKey? sessionKey = null,
        DateTime? time = null
    );

    /// <summary>
    /// Bulk encrypt literal texts
    /// </summary>
    IList<IEncryptedMessage> BulkEncrypt(
        IList<string> texts,
        ISessionKey? sessionKey = null,
        DateTime? time = null
    );
    
    /// <summary>
    /// Encrypt a session key
    /// </summary>
    IPacketList EncryptSessionKey(ISessionKey sessionKey);
}
