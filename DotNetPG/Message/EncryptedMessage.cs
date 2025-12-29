// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
/// OpenPGP encrypted message class
/// </summary>
public class EncryptedMessage : BaseMessage, IEncryptedMessage
{
    private ISessionKey? _sessionKey;
 
    public EncryptedMessage(IPacketList packetList): base(packetList)
    {
        EncryptedPacket = AssertEncryptedPacket(packetList);
        _sessionKey = null;
    }

    public static EncryptedMessage FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static EncryptedMessage FromBytes(byte[] bytes)
    {
        return new EncryptedMessage(Packet.PacketList.Decode(bytes));
    }

    /// <summary>
    /// Decrypt encrypted session keys.
    /// Using private keys or passwords (not both).
    /// </summary>
    public static ISessionKey DecryptSessionKey(
        IPacketList packetList,
        IList<IPrivateKey> decryptionKeys,
        IList<string> passwords
    )
    {
        var eskPackets = packetList.Packets.OfType<IEncryptedSessionKey>().ToList();
        if (eskPackets.Count == 0)
        {
            throw new Exception("No encrypted session key in packet list.");
        }
        
        IList<string> errors = [];
        IList<ISessionKey> sessionKeys = [];
        if (passwords.Count > 0)
        {
            var skeskPackets = eskPackets.OfType<ISymmetricKeyEncryptedSessionKey>().ToList();
            foreach (var skesk in skeskPackets)
            {
                foreach (var password in passwords)
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

        if (sessionKeys.Count == 0 && decryptionKeys.Count > 0)
        {
            var pkeskPackets = eskPackets.OfType<IPublicKeyEncryptedSessionKey>().ToList();
            foreach (var pkesk in pkeskPackets)
            {
                foreach (var key in decryptionKeys)
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
            throw new Exception(string.Join("\n", ["Session key decryption failed.", ..errors]));
        }
        return sessionKeys[0];
    }

    public IEncryptedDataPacket EncryptedPacket { get; }

    public ISessionKey? SessionKey => _sessionKey;

    public ILiteralMessage Decrypt(IList<IPrivateKey> decryptionKeys, IList<string> passwords)
    {
        if (decryptionKeys.Count == 0 && passwords.Count == 0)
        {
            throw new ArgumentException("No decryption keys or passwords provided.");
        }
        _sessionKey = DecryptSessionKey(PacketList, decryptionKeys, passwords);
        var packetList = EncryptedPacket.DecryptWithSessionKey(_sessionKey).PacketList;
        return packetList != null ? new LiteralMessage(packetList) : throw new Exception("Decrypt with session key failed.");
    }

    private static IEncryptedDataPacket AssertEncryptedPacket(IPacketList packetList)
    {
        var encryptedPackets = packetList.Packets.OfType<IEncryptedDataPacket>().ToList();
        return encryptedPackets.Count == 0 ? throw new Exception("No encrypted data packet in packet list.") : encryptedPackets[0];
    }
}
