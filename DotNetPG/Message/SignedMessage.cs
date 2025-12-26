// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Enum;
using Packet;
using Type;

/// <summary>
/// Class that represents an OpenPGP cleartext signed message.
/// See RFC 9580, section 7.
/// </summary>
public class SignedMessage(string text, ISignature signature) : CleartextMessage(text), ISignedMessage
{
    public static SignedMessage FromArmored(string armored)
    {
        var armor = Common.Armor.Decode(armored);
        var packetList = PacketList.Decode(armor.Data).Packets.OfType<ISignaturePacket>().ToList();
        return new SignedMessage(armor.Text, new Signature(packetList));
    }
    
    public string Armor()
    {
        var hashAlgos = signature.Packets.Select(
            packet => packet.HashAlgorithm.ToString()
        ).ToList();
        return Common.Armor.Encode(ArmorType.SignedMessage, signature.PacketList.Encode(), Text, hashAlgos);
    }

    public ISignature Signature => signature;

    public IList<IVerification> Verify(IList<IKey> verificationKeys, DateTime? time = null)
    {
        return signature.VerifyCleartext(verificationKeys, this, time);
    }
}