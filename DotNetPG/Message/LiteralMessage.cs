// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Common;
using Enum;
using Packet;
using Packet.Key;
using Type;

/// <summary>
/// OpenPGP literal message class
/// </summary>
public class LiteralMessage : BaseMessage, ILiteralMessage
{
    public LiteralMessage(IPacketList packetList) : base(packetList)
    {
       var packets = UnwrapCompressed(packetList).Packets;
       var ldPackets = packets.OfType<ILiteralData>().ToList();
       if (ldPackets.Count == 0)
       {
           throw new ArgumentException("No literal data in packet list.");
       }

       LiteralData = ldPackets[0];
       Signature = new Signature(packets.OfType<ISignaturePacket>().ToList());
    }

    public static LiteralMessage FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }
    
    public static LiteralMessage FromBytes(byte[] bytes)
    {
        return new LiteralMessage(Packet.PacketList.Decode(bytes));
    }

    public static LiteralMessage FromText(string text)
    {
        return new LiteralMessage(
            new PacketList(
                [Packet.LiteralData.FromText(text)]
            )
        );
    }

    public static LiteralMessage FromLiteralData(
        byte[] data,
        string filename = "",
        DateTime? time = null
    )
    {
        return new LiteralMessage(
            new PacketList(
                [new LiteralData(data, LiteralFormat.Binary, filename, time)]
            )
        );
    }
    
    /// <summary>
    /// Generate a new session key object.
    /// Taking the algorithm preferences of the passed encryption keys, if any.
    /// </summary>
    public static ISessionKey GenerateSessionKey(
        IList<IKey> encryptionKeys,
        SymmetricAlgorithm defaultSymmetric = SymmetricAlgorithm.Aes256
    )
    {
        IList<SymmetricAlgorithm> preferredSymmetrics = [];
        foreach (var key in encryptionKeys)
        {
            if (preferredSymmetrics.Count == 0)
            {
                preferredSymmetrics = key.PreferredSymmetrics;
            }
            else
            {
                preferredSymmetrics = preferredSymmetrics.TakeWhile(
                    prefer => key.PreferredSymmetrics.Contains(prefer)
                ).ToList();
            }
        }
        var symmetric = preferredSymmetrics.Count > 0 ? preferredSymmetrics[0] : defaultSymmetric;

        IList<AeadAlgorithm> preferredAeads = [
            AeadAlgorithm.Ocb,
            AeadAlgorithm.Gcm,
            AeadAlgorithm.Eax
        ];
        var aeadProtect = Config.AeadProtect;
        foreach (var key in encryptionKeys)
        {
            if (key.AeadSupported)
            {
                preferredAeads = preferredAeads.TakeWhile(
                    prefer => key.PreferredAeads(symmetric).Contains(prefer)
                ).ToList();
                aeadProtect = true;
            }
            else
            {
                aeadProtect = false;
                break;
            }
        }
        var aead = preferredAeads.Count > 0 ? preferredAeads[0] : Config.PreferredAead;

        return SessionKey.ProduceKey(symmetric, aeadProtect ? aead : null);
    }

    /// <summary>
    /// Encrypt a session key either with public keys, passwords, or both at once.
    /// </summary>
    public static IPacketList EncryptSessionKey(
        ISessionKey sessionKey,
        IList<IKey> encryptionKeys,
        IList<string> passwords
    )
    {
        if (encryptionKeys.Count == 0 && passwords.Count == 0)
        {
            throw new ArgumentException("No encryption keys or passwords provided.");
        }

        var pkeskPackets = encryptionKeys.Select(key =>
            PublicKeyEncryptedSessionKey.EncryptSessionKey(sessionKey, key.GetEncryptionKeyPacket())
        );
        var skeskPackets = passwords.Select(
            password => SymmetricKeyEncryptedSessionKey.EncryptSessionKey(
                password, sessionKey.Symmetric, sessionKey, sessionKey.Aead
            )
        );
        return new PacketList([..pkeskPackets, ..skeskPackets]);
    }

    public ILiteralData LiteralData { get; }

    public ISignature Signature { get; }

    public ILiteralMessage Sign(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        IList<ISignaturePacket> signaturePackets = [
            ..UnwrapCompressed(PacketList).Packets.OfType<ISignaturePacket>(),
            ..SignDetached(signingKeys, recipients, notationData, time).Packets
        ];
        IList<OnePassSignature> opsPackets = [];
        foreach (var packet in signaturePackets)
        {
            var index = signaturePackets.IndexOf(packet);
            opsPackets.Add(OnePassSignature.FromSignature(packet, index == 0 ? 1 : 0));
        }

        // innermost OPS refers to the first signature packet
        return new LiteralMessage(new PacketList([
            ..opsPackets.Reverse(),
            LiteralData,
            ..signaturePackets
        ]));
    }

    public ISignature SignDetached(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        if (signingKeys.Count == 0)
        {
            throw new ArgumentException("No signing keys provided.");
        }
        var signatures = signingKeys.Select(
            key => SignaturePacket.CreateLiteralData(
                key.SecretKeyPacket, LiteralData, recipients ?? [], notationData, time
            )
        );
        return new Signature([..signatures]);
    }

    public IList<IVerification> Verify(
        IList<IKey> verificationKeys,
        DateTime? time = null
    )
    {
        return Signature.Verify(verificationKeys, LiteralData, time);
    }

    public IList<IVerification> VerifyDetached(
        IList<IKey> verificationKeys,
        ISignature signature,
        DateTime? time = null
    )
    {
        return signature.Verify(verificationKeys, LiteralData, time);
    }

    public IEncryptedMessage Encrypt(
        IList<IKey> encryptionKeys,
        IList<string> passwords,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    )
    {
        var sessionKey = GenerateSessionKey(encryptionKeys, symmetric);
        var addPadding = sessionKey.Aead != null;
        if (encryptionKeys.Any(key => key.Version != 6))
        {
            addPadding = false;
        }
        var packetList = addPadding ? new PacketList([..PacketList.Packets, Padding.CreatePadding()]) : PacketList;

        return new EncryptedMessage(new PacketList([
            ..EncryptSessionKey(sessionKey, encryptionKeys, passwords).Packets,
            SymEncryptedIntegrityProtectedData.EncryptPacketsWithSessionKey(sessionKey, packetList, sessionKey.Aead)
        ]));
    }

    public ILiteralMessage Compress(
        CompressionAlgorithm algorithm = CompressionAlgorithm.Uncompressed
    )
    {
        if (algorithm != CompressionAlgorithm.Uncompressed)
        {
            return new LiteralMessage(
                new PacketList(
                    [CompressedData.FromPacketList(UnwrapCompressed(PacketList),
                    algorithm)]
                )
            );
        }
        return this;
    }

    private static IPacketList UnwrapCompressed(IPacketList packetList)
    {
        var compressedPackets = packetList.Packets.OfType<ICompressedData>().ToList();
        return compressedPackets.Count > 0 ? compressedPackets[0].PacketList : packetList;
    }
}
