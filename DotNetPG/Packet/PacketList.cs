// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Packet list class
/// </summary>
public class PacketList(IList<IPacket> packets) : IPacketList
{
    public IPacket this[int index] => packets[index];

    public IList<IPacket> Packets => packets.AsReadOnly();

    public byte[] Encode()
    {
        return packets.SelectMany(packet => packet.Encode()).ToArray();
    }

    public int[] IndexOfType(PacketType[] types)
    {
        IList<int> indexes = [];
        for (var i = 0; i < packets.Count; i++)
        {
            var packet = packets[i];
            if (types.Contains(packet.Type))
            {
                indexes.Add(i);
            }
        }
        return indexes.ToArray();
    }
    
    /// <summary>
    ///     Decode packets from bytes
    /// </summary>
    public static PacketList Decode(byte[] bytes)
    {
        IList<IPacket> packets = [];
        var data = Arrays.Clone(bytes);
        while (data.Length > 0)
        {
            var reader = PacketReader.Read(data);
            data = data.Skip(reader.Length).ToArray();
            IPacket? packet = reader.Type switch
            {
                PacketType.PublicKeyEncryptedSessionKey => PublicKeyEncryptedSessionKey.FromBytes(reader.Data),
                PacketType.Signature => SignaturePacket.FromBytes(reader.Data),
                PacketType.SymmetricKeyEncryptedSessionKey => SymmetricKeyEncryptedSessionKey.FromBytes(reader.Data),
                PacketType.OnePassSignature => OnePassSignature.FromBytes(reader.Data),
                PacketType.SecretKey => SecretKey.FromBytes(reader.Data),
                PacketType.PublicKey => PublicKey.FromBytes(reader.Data),
                PacketType.SecretSubkey => SecretSubkey.FromBytes(reader.Data),
                PacketType.CompressedData => CompressedData.FromBytes(reader.Data),
                PacketType.SymEncryptedData => SymEncryptedData.FromBytes(reader.Data),
                PacketType.Marker => new Marker(),
                PacketType.LiteralData => LiteralData.FromBytes(reader.Data),
                PacketType.Trust => Trust.FromBytes(reader.Data),
                PacketType.UserId => UserId.FromBytes(reader.Data),
                PacketType.PublicSubkey => PublicSubkey.FromBytes(reader.Data),
                PacketType.UserAttribute => UserAttribute.FromBytes(reader.Data),
                PacketType.SymEncryptedIntegrityProtectedData => SymEncryptedIntegrityProtectedData.FromBytes(
                    reader.Data
                ),
                PacketType.AeadEncryptedData => AeadEncryptedData.FromBytes(reader.Data),
                PacketType.Padding => new Padding(reader.Data),
                _ => null
            };
            if (packet != null) packets.Add(packet);
        }

        return new PacketList(packets.ToArray());
    }
}
