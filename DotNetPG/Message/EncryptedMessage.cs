// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;

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

    public IEncryptedDataPacket EncryptedPacket { get; }

    public ISessionKey? SessionKey => _sessionKey;

    public ILiteralMessage Decrypt(IList<IPrivateKey> decryptionKeys, IList<string> passwords)
    {
        var decryptor = new Decryptor()
            .WithDecryptionKeys(decryptionKeys)
            .WithPasswords(passwords);
        var literalMessage = decryptor.Decrypt(this);
        _sessionKey = decryptor.SessionKey;
        return literalMessage;
    }

    private static IEncryptedDataPacket AssertEncryptedPacket(IPacketList packetList)
    {
        var encryptedPackets = packetList.Packets.OfType<IEncryptedDataPacket>().ToList();
        return encryptedPackets.Count == 0 ?
            throw new Exception("No encrypted data packet in packet list.") :
            encryptedPackets[0];
    }
}
