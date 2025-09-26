// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Abstract OpenPGP key class
/// </summary>
public abstract class BaseKey : IKey
{
    private readonly IKeyPacket _keyPacket;

    private readonly ISignaturePacket[] _revocationSignatures;

    private readonly ISignaturePacket[] _directSignatures;

    private readonly IUser[] _users;

    private readonly ISubkey[] _subkeys;

    private readonly IPacketList _packetList;

    protected BaseKey(IPacketList packetList)
    {
        var keyPackets = packetList.Packets.TakeWhile(packet => packet is IKeyPacket).ToList();
        switch (keyPackets.Count)
        {
            case 0:
                throw new Exception("Key packet not found in packet list.");
            case > 1:
                throw new Exception("Key block contains multiple key packets.");
        }
        _keyPacket = keyPackets.OfType<IKeyPacket>().First();

        var remainPackets = packetList.Packets.SkipWhile(packet => packet is IKeyPacket).ToList();
        _revocationSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();

        remainPackets = remainPackets.SkipWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).ToList();
        _directSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsDirectKey;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();

        remainPackets = remainPackets.SkipWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsDirectKey;
            }
            return false;
        }).ToList();

        IUserIdPacket? userIdPacket = null;
        var users = new List<IUser>();
        var revocationSignatures = new List<ISignaturePacket>();
        var selfSignatures = new List<ISignaturePacket>();
        var otherSignatures  = new List<ISignaturePacket>();
        var userPackets = remainPackets.TakeWhile(packet => packet is not ISubkeyPacket).ToList();
        foreach (var packet in userPackets)
        {
            if (packet is IUserIdPacket userId)
            {
                if (userIdPacket != null)
                {
                    users.Add(new User(
                        this,
                        userIdPacket,
                        revocationSignatures.ToArray(),
                        selfSignatures.ToArray(),
                        otherSignatures.ToArray())
                    );
                    revocationSignatures.Clear();
                    selfSignatures.Clear();
                    otherSignatures.Clear();
                }
                userIdPacket = userId;
            }

            if (packet is ISignaturePacket signature)
            {
                if (signature.IsCertRevocation)
                {
                    revocationSignatures.Add(signature);
                }

                if (signature.IsCertification)
                {
                    if (Arrays.AreEqual(signature.IssuerKeyId, _keyPacket.KeyId))
                    {
                        selfSignatures.Add(signature);
                    }
                    else
                    {
                        otherSignatures.Add(signature);
                    }
                }
            }
        }
        if (userIdPacket != null)
        {
            users.Add(new User(
                this,
                userIdPacket,
                revocationSignatures.ToArray(),
                selfSignatures.ToArray(),
                otherSignatures.ToArray())
            );
        }
        _users = users.ToArray();

        ISubkeyPacket? subkeyPacket = null;
        var subkeys = new List<ISubkey>();
        revocationSignatures.Clear();
        var bindingSignatures = new List<ISignaturePacket>();
        var subkeyPackets = remainPackets.SkipWhile(packet => packet is not ISubkeyPacket).ToList();
        foreach (var packet in subkeyPackets)
        {
            if (packet is ISubkeyPacket subkey)
            {
                if (subkeyPacket != null)
                {
                    subkeys.Add(new Subkey(
                        this,
                        subkeyPacket,
                        revocationSignatures.ToArray(),
                        bindingSignatures.ToArray()
                    ));
                    revocationSignatures.Clear();
                    bindingSignatures.Clear();
                }
                subkeyPacket = subkey;
            }
            if (packet is ISignaturePacket signature)
            {
                if (signature.IsSubkeyRevocation)
                {
                    revocationSignatures.Add(signature);
                }
                if (signature.IsSubkeyBinding)
                {
                    bindingSignatures.Add(signature);
                }
            }
        }
        if (subkeyPacket != null)
        {
            subkeys.Add(new Subkey(
                this,
                subkeyPacket,
                revocationSignatures.ToArray(),
                bindingSignatures.ToArray()
            ));
        }
        _subkeys = subkeys.ToArray();

        _packetList = new Packet.PacketList([
            _keyPacket,
            .._revocationSignatures,
            .._directSignatures,
            .._users.SelectMany(user => user.PacketList.Packets),
            .._subkeys.SelectMany(subkey => subkey.PacketList.Packets)
        ]);
    }

    public IKeyPacket  KeyPacket => _keyPacket;

    public int Version => _keyPacket.Version;

    public DateTime? ExpirationTime => KeyExpiration(_directSignatures);

    public DateTime CreationTime => _keyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => _keyPacket.KeyAlgorithm;

    public byte[] Fingerprint => _keyPacket.Fingerprint;

    public byte[] KeyId => _keyPacket.KeyId;

    public int KeyLength => _keyPacket.KeyLength;

    public ISignaturePacket[] RevocationSignatures => _revocationSignatures;

    public ISignaturePacket[] DirectSignatures => _directSignatures;

    public IUser[] Users => _users;

    public ISubkey[] Subkeys => _subkeys;

    public IUser? PrimaryUser { get; }

    public bool IsPrivate => _keyPacket is ISecretKeyPacket;

    public SymmetricAlgorithm[] PreferredSymmetrics { get; }

    public bool AeadSupported { get; }

    public IPacketList PacketList => _packetList;

    public AeadAlgorithm[] PreferredAeads(SymmetricAlgorithm symmetric)
    {
        throw new NotImplementedException();
    }

    public bool IsRevoked(IKey? verifyKey = null, ISignaturePacket? certificate = null, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public bool IsCertified(IKey? verifyKey = null, ISignaturePacket? certificate = null, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public bool Verify(DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey CertifyBy(IPrivateKey signKey, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IKey RevokeBy(IPrivateKey signKey, string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public static DateTime? KeyExpiration(IList<ISignaturePacket> signatures)
    {
        var list = signatures.ToList();
        list.Sort((a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        foreach (var signature in list)
        {
            if (signature.KeyExpirationTime > 0)
            {
                var creationTime = new DateTimeOffset((DateTime)signature.CreationTime!);
                var dto = creationTime.AddSeconds(signature.KeyExpirationTime);
                return dto.DateTime;
            }

            if (signature.ExpirationTime != null)
            {
                return signature.ExpirationTime;
            }
        }
        return null;
    }
}
