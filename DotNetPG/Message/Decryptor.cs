// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;
using Org.BouncyCastle.Utilities;

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

    public ISessionKey DecryptSessionKey(IPacketList packetList)
    {
        var eskPackets = packetList.Packets.OfType<IEncryptedSessionKey>().ToList();
        if (eskPackets.Count == 0)
        {
            throw new Exception("No encrypted session key in packet list.");
        }
        
        IList<string> errors = [];
        IList<ISessionKey> sessionKeys = [];
        if (_passwords.Count > 0)
        {
            var skeskPackets = eskPackets.OfType<ISymmetricKeyEncryptedSessionKey>().ToList();
            foreach (var skesk in skeskPackets)
            {
                foreach (var password in _passwords)
                {
                    try
                    {
                        var sessionKey = skesk.Decrypt(password).SessionKey;
                        if (sessionKey != null)
                        {
                            sessionKeys.Add(sessionKey);
                        }
                    }
                    catch (Exception e)
                    {
                        errors.Add(e.Message);
                    }
                }
            }
        }

        if (sessionKeys.Count == 0 && _decryptionKeys.Count > 0)
        {
            var pkeskPackets = eskPackets.OfType<IPublicKeyEncryptedSessionKey>().ToList();
            foreach (var pkesk in pkeskPackets)
            {
                foreach (var key in _decryptionKeys)
                {
                    var keyPacket = key.GetEncryptionKeyPacket() as ISecretKeyPacket;
                    if (pkesk.KeyAlgorithm == keyPacket?.KeyAlgorithm && Arrays.AreEqual(pkesk.KeyId, keyPacket.KeyId))
                    {
                        try
                        {
                            var sesionKey = pkesk.Decrypt(keyPacket).SessionKey;
                            if (sesionKey != null)
                            {
                                sessionKeys.Add(sesionKey);
                            }
                        }
                        catch (Exception e)
                        {
                            errors.Add(e.Message);
                        }
                    }
                }
            }
        }

        if (sessionKeys.Count == 0)
        {
            throw new Exception(
                string.Join("\n", ["Session key decryption failed.", ..errors])
            );
        }
        return sessionKeys[0];
    }
}
