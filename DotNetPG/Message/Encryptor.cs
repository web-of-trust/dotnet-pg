// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Common;
using Enum;
using Packet;
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
            return EncryptMessage(message.Compress(_compression));
        }
        return EncryptMessage(message.Sign(
            _signingKeys, _encryptionKeys, _notationData, time
        ).Compress(_compression));
    }

    public IEncryptedMessage Encrypt(byte[] literalData, DateTime? time = null)
    {
        return Encrypt(LiteralMessage.FromLiteralData(literalData, time: time), time);
    }

    public IEncryptedMessage Encrypt(string text, DateTime? time = null)
    {
        return Encrypt(LiteralMessage.FromText(text), time);
    }

    public IList<IEncryptedMessage> BulkEncrypt(
        IList<ILiteralMessage> messages,
        ISessionKey? sessionKey = null,
        DateTime? time = null
    )
    {
        sessionKey ??= new SessionKeyGenerator()
            .WithEncryptionKeys(_encryptionKeys)
            .WithDefaultSymmetric(_symmetric)
            .Generate();
        var eskPacketList = new Encryptor()
            .WithEncryptionKeys(_encryptionKeys)
            .WithPasswords(_passwords)
            .EncryptSessionKey(sessionKey).Packets;

        var addPadding = sessionKey.Aead != null;
        if (_encryptionKeys.Any(key => key.Version != 6))
        {
            addPadding = false;
        }
        var encryptedMessages = messages.Select(IEncryptedMessage (message) =>
        {
            if (_signingKeys.Count != 0)
            {
                message = message.Sign(
                    _signingKeys, _encryptionKeys, _notationData, time
                );
            }
            message = message.Compress(_compression);
            var packetList = addPadding ?
                new PacketList([..message.PacketList.Packets, Padding.CreatePadding()]) :
                message.PacketList;
            return new EncryptedMessage(new PacketList([
                ..eskPacketList,
                SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(
                    sessionKey, packetList, sessionKey.Aead
                )
            ]));
        });
        return encryptedMessages.ToList();
    }

    public IList<IEncryptedMessage> BulkEncrypt(
        IList<string> texts,
        ISessionKey? sessionKey = null,
        DateTime? time = null
    )
    {
        var messages = texts.Select(LiteralMessage.FromText);
        return BulkEncrypt(messages.ToList(), sessionKey, time);
    }

    public IPacketList EncryptSessionKey(ISessionKey sessionKey)
    {
        if (_encryptionKeys.Count == 0 && _passwords.Count == 0)
        {
            throw new ArgumentException(
                "No encryption keys or passwords provided."
            );
        }

        var pkeskPackets = _encryptionKeys.Select(key =>
            PublicKeyEncryptedSessionKey.EncryptSessionKey(
                sessionKey, key.GetEncryptionKeyPacket()
            )
        );
        var skeskPackets = _passwords.Select(
            password => SymmetricKeyEncryptedSessionKey.EncryptSessionKey(
                password, sessionKey.Symmetric, sessionKey, sessionKey.Aead
            )
        );
        return new PacketList([..pkeskPackets, ..skeskPackets]);
    }

    public IEncryptedMessage EncryptMessage(ILiteralMessage message)
    {
        var sessionKey = new SessionKeyGenerator()
            .WithEncryptionKeys(_encryptionKeys)
            .WithDefaultSymmetric(_symmetric)
            .Generate();
        var addPadding = sessionKey.Aead != null;
        if (_encryptionKeys.Any(key => key.Version != 6))
        {
            addPadding = false;
        }
        var packetList = addPadding ?
            new PacketList([..message.PacketList.Packets, Padding.CreatePadding()]) :
            message.PacketList;

        return new EncryptedMessage(new PacketList([
            ..new Encryptor()
                .WithEncryptionKeys(_encryptionKeys)
                .WithPasswords(_passwords)
                .EncryptSessionKey(sessionKey).Packets,
            SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(
                sessionKey, packetList, sessionKey.Aead
            )
        ]));
    }
    
}
