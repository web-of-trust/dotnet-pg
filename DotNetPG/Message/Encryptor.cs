// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Common;
using Enum;
using Type;

/// <summary>
/// Encryptor
/// </summary>
public class Encryptor : IEncryptor
{
    private IList<IKey> _encryptionKeys = [];
    private IList<string> _passwords = [];
    private IList<IPrivateKey> _signingKeys = [];
    private SymmetricAlgorithm _symmetric = Config.PreferredSymmetric;
    private CompressionAlgorithm _compression  = Config.PreferredCompression;
    private INotationData? _notationData = null;

    public Encryptor WithEncryptionKeys(IList<IKey> encryptionKeys)
    {
        _encryptionKeys = encryptionKeys;
        return this;
    }

    public Encryptor WithPasswords(IList<string> passwords)
    {
        _passwords = passwords;
        return this;
    }

    public Encryptor WithSigningKeys(IList<IPrivateKey> signingKeys)
    {
        _signingKeys = signingKeys;
        return this;
    }

    public Encryptor WithSymmetric(SymmetricAlgorithm symmetric)
    {
        _symmetric = symmetric;
        return this;
    }

    public Encryptor WithCompression(CompressionAlgorithm compression)
    {
        _compression = compression;
        return this;
    }

    public Encryptor WithNotationData(INotationData? notationData = null)
    {
        _notationData = notationData;
        return this;
    }

    public IEncryptedMessage Encrypt(ILiteralMessage message, DateTime? time = null)
    {
        if (_signingKeys.Count == 0)
        {
            return message.Compress(_compression).Encrypt(
                _encryptionKeys, _passwords, _symmetric
            );
        }
        return message.Sign(
            _signingKeys, _encryptionKeys, _notationData, time
        ).Compress(_compression).Encrypt(
            _encryptionKeys, _passwords, _symmetric
        );
    }

    public IEncryptedMessage Encrypt(byte[] literalData, DateTime? time = null)
    {
        return Encrypt(LiteralMessage.FromLiteralData(literalData, time: time), time);
    }

    public IEncryptedMessage Encrypt(string text, DateTime? time = null)
    {
        return Encrypt(LiteralMessage.FromText(text), time);
    }
}
