// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.


namespace DotNetPG.Message;

using Enum;
using Packet;
using Type;

/// <summary>
/// Class that represents a detacted OpenPGP signature.
/// </summary>
public class Signature : ISignature
{
    private IList<ISignaturePacket> _packets;

    private IList<byte[]> _signingKeyIDs;
    
    private IList<Exception> _verificationErrors;

    public Signature(IList<ISignaturePacket> packets)
    {
        _packets = packets;
        PacketList = new PacketList(packets.OfType<IPacket>().ToList());
        _signingKeyIDs = packets.Select(signature => signature.IssuerKeyId).ToList();
        _verificationErrors = [];
    }

    public static ISignature FromArmored(string armored)
    {
        return FromBytes(Common.Armor.Decode(armored).Data);
    }

    public static ISignature FromBytes(byte[] bytes)
    {
        return new Signature(Packet.PacketList.Decode(bytes).Packets.OfType<ISignaturePacket>().ToList());
    }

    public IList<ISignaturePacket> Packets => _packets.AsReadOnly();
    
    public IPacketList PacketList { get; }

    public IList<byte[]> SigningKeyIDs => _signingKeyIDs.AsReadOnly();

    public IList<Exception> VerificationErrors => _verificationErrors.AsReadOnly();

    public IList<IVerification> Verify(IList<IKey> verificationKeys, ILiteralData literalData, DateTime? time = null)
    {
        if (verificationKeys.Count == 0)
        {
            throw new ArgumentException("No verification keys provided.");
        }

        IList<IVerification> verifications = [];

        foreach (var signature in _packets)
        {
            foreach (var key in verificationKeys)
            {
                IKeyPacket? keyPacket = null;
                try
                {
                    keyPacket = key switch
                    {
                        IPrivateKey privateKey => privateKey.PublicKey.GetSigningKeyPacket(signature.IssuerKeyId),
                        _ => key.GetSigningKeyPacket(signature.IssuerKeyId),
                    };
                }
                catch (Exception e)
                {
                    _verificationErrors.Add(e);
                }

                if (keyPacket != null)
                {
                    var isVerified = false;
                    var verificationError = "";
                    try
                    {
                        isVerified = signature.Verify(keyPacket, literalData.SignBytes(), time);
                    }
                    catch (Exception e)
                    {
                        _verificationErrors.Add(e);
                        verificationError = e.ToString();
                    }

                    verifications.Add(
                        new Verification(
                            keyPacket.KeyId,
                            signature,
                            verificationError,
                            isVerified,
                            key.Users.Select(user => user.UserId).ToList()
                        )
                    );
                }
            }
        }

        return verifications;
    }

    public IList<IVerification> VerifyCleartext(IList<IKey> verificationKeys, ICleartextMessage cleartext, DateTime? time = null)
    {
        return Verify(verificationKeys, LiteralData.FromText(cleartext.Text), time);
    }

    public string Armor() => Common.Armor.Encode(ArmorType.Signature, PacketList.Encode());
}