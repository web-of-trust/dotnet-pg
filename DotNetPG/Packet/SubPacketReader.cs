// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Enum;
using SubPacket;
using Type;
using System.Buffers.Binary;

/// <summary>
///     Sub packet reader class
/// </summary>
public sealed class SubPacketReader(int type, byte[] data, int length)
{
    /// <summary>
    ///     Get type
    /// </summary>
    public int Type => type;

    /// <summary>
    ///     Get data
    /// </summary>
    public byte[] Data => data;

    /// <summary>
    ///     Get length
    /// </summary>
    public int Length => length;

    public static SubPacketReader Read(byte[] bytes)
    {
        var offset = 0;
        var header = bytes[offset++];

        int length;
        if (header < 192)
        {
            length = header;
        }
        else if (header < 255)
        {
            length = ((header - 192) << 8) + bytes[offset++] + 192;
        }
        else
        {
            length = BinaryPrimitives.ReadInt32BigEndian(
                bytes.Take(4).ToArray()
            );
            offset += 4;
        }

        return new SubPacketReader(
            bytes[offset],
            bytes.Skip(offset + 1).Take(length - 1).ToArray(),
            offset + length
        );
    }

    public static ISubPacket[] ReadSignatureSubPackets(byte[] bytes)
    {
        var subPackets = new List<ISubPacket>();
        while (bytes.Length > 0)
        {
            var reader = Read(bytes);
            bytes = bytes.Skip(reader.Length).ToArray();
            var critical = (reader.Type & 0x80) != 0;
            var type = (SignatureSubPacketType)(reader.Type & 0x7f);
            switch (type)
            {
                case SignatureSubPacketType.EmbeddedSignature:
                    subPackets.Add(new EmbeddedSignature(reader.Data, critical));
                    break;
                case SignatureSubPacketType.ExportableCertification:
                    subPackets.Add(new ExportableCertification(reader.Data, critical));
                    break;
                case SignatureSubPacketType.Features:
                    subPackets.Add(new Features(reader.Data, critical));
                    break;
                case SignatureSubPacketType.IntendedRecipientFingerprint:
                    subPackets.Add(new IntendedRecipientFingerprint(reader.Data, critical));
                    break;
                case SignatureSubPacketType.IssuerFingerprint:
                    subPackets.Add(new IssuerFingerprint(reader.Data, critical));
                    break;
                case SignatureSubPacketType.IssuerKeyId:
                    subPackets.Add(new IssuerKeyId(reader.Data, critical));
                    break;
                case SignatureSubPacketType.KeyExpirationTime:
                    subPackets.Add(new KeyExpirationTime(reader.Data, critical));
                    break;
                case SignatureSubPacketType.KeyFlags:
                    subPackets.Add(new KeyFlags(reader.Data, critical));
                    break;
                case SignatureSubPacketType.KeyServerPreferences:
                    subPackets.Add(new KeyServerPreferences(reader.Data, critical));
                    break;
                case SignatureSubPacketType.NotationData:
                    subPackets.Add(new NotationData(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PolicyUri:
                    subPackets.Add(new PolicyUri(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredAeadAlgorithms:
                    subPackets.Add(new PreferredAeadAlgorithms(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredAeadCiphers:
                    subPackets.Add(new PreferredAeadCiphers(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredCompressionAlgorithms:
                    subPackets.Add(new PreferredCompressionAlgorithms(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredHashAlgorithms:
                    subPackets.Add(new PreferredHashAlgorithms(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredKeyServer:
                    subPackets.Add(new PreferredKeyServer(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PreferredSymmetricAlgorithms:
                    subPackets.Add(new PreferredSymmetricAlgorithms(reader.Data, critical));
                    break;
                case SignatureSubPacketType.PrimaryUserId:
                    subPackets.Add(new PrimaryUserId(reader.Data, critical));
                    break;
                case SignatureSubPacketType.RegularExpression:
                    subPackets.Add(new RegularExpression(reader.Data, critical));
                    break;
                case SignatureSubPacketType.Revocable:
                    subPackets.Add(new Revocable(reader.Data, critical));
                    break;
                case SignatureSubPacketType.RevocationKey:
                    subPackets.Add(new RevocationKey(reader.Data, critical));
                    break;
                case SignatureSubPacketType.RevocationReason:
                    subPackets.Add(new RevocationReason(reader.Data, critical));
                    break;
                case SignatureSubPacketType.SignatureCreationTime:
                    subPackets.Add(new SignatureCreationTime(reader.Data, critical));
                    break;
                case SignatureSubPacketType.SignatureExpirationTime:
                    subPackets.Add(new SignatureExpirationTime(reader.Data, critical));
                    break;
                case SignatureSubPacketType.SignatureTarget:
                    subPackets.Add(new SignatureTarget(reader.Data, critical));
                    break;
                case SignatureSubPacketType.SignerUserId:
                    subPackets.Add(new SignerUserId(reader.Data, critical));
                    break;
                case SignatureSubPacketType.TrustSignature:
                    subPackets.Add(new TrustSignature(reader.Data, critical));
                    break;
                default:
                    subPackets.Add(new SignatureSubPacket(reader.Type, reader.Data, critical));
                    break;
            }
        }

        return subPackets.ToArray();
    }
}