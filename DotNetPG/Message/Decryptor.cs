// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using DotNetPG.Type;

namespace DotNetPG.Message;

/// <summary>
/// Decryptor
/// </summary>
public class Decryptor : IDecryptor
{
    private IList<IPrivateKey> _decryptionKeys = [];
    private IList<string> _passwords = [];

    public Decryptor WithDecryptionKeys(IList<IPrivateKey> decryptionKeys)
    {
        _decryptionKeys = decryptionKeys;
        return this;
    }

    public Decryptor WithPasswords(IList<string> passwords)
    {
        _passwords = passwords;
        return this;
    }

    public ILiteralMessage Decrypt(IEncryptedMessage message)
    {
        return message.Decrypt(_decryptionKeys, _passwords);
    }

    public ILiteralMessage Decrypt(string messageData)
    {
        return Decrypt(EncryptedMessage.FromArmored(messageData));
    }
}
