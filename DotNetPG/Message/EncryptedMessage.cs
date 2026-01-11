// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;

/// <summary>
/// OpenPGP encrypted message class
/// </summary>
public class EncryptedMessage(IPacketList packetList) : BaseMessage(packetList), IEncryptedMessage
{
    public static IEncryptedMessage FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static IEncryptedMessage FromBytes(byte[] bytes)
    {
        return new EncryptedMessage(Packet.PacketList.Decode(bytes));
    }

    public IEncryptedDataPacket EncryptedPacket { get; } = AssertEncryptedPacket(packetList);

    public IList<IEncryptedSessionKey> EskPackets { get; } = packetList.Packets.OfType<IEncryptedSessionKey>().ToList();

    public ILiteralMessage Decrypt(IList<IPrivateKey> decryptionKeys, IList<string> passwords)
    {
        return new Decryptor()
            .WithDecryptionKeys(decryptionKeys)
            .WithPasswords(passwords)
            .Decrypt(this);
    }

    private static IEncryptedDataPacket AssertEncryptedPacket(IPacketList packetList)
    {
        var encryptedPackets = packetList.Packets.OfType<IEncryptedDataPacket>().ToList();
        return encryptedPackets.Count == 0 ?
            throw new Exception("No encrypted data packet in packet list.") :
            encryptedPackets[0];
    }
}
