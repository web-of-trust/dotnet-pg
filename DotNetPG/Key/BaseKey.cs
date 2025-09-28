// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
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

    private readonly IUser? _primaryUser;
    
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
        Array.Sort(_revocationSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

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
        Array.Sort(_directSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

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
        Array.Sort(_users, (a, b) =>
        {
            var aTime = a.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            var bTime = b.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        _primaryUser = users.Find(user => user.IsPrimary);

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
        Array.Sort(_subkeys, (a, b) => (int)(new DateTimeOffset(a.CreationTime).ToUnixTimeSeconds() - new DateTimeOffset(b.CreationTime).ToUnixTimeSeconds()));

        IList<IPacket> packets = [
            _keyPacket,
            .._revocationSignatures,
            .._directSignatures,
            .._users.SelectMany(user => user.PacketList.Packets),
            .._subkeys.SelectMany(subkey => subkey.PacketList.Packets),
        ];
        if (Version == (int) KeyVersion.V6)
        {
            packets.Add(Padding.CreatePadding());
        }
        _packetList = new PacketList(packets.ToArray());
    }

    public IKeyPacket KeyPacket => _keyPacket;

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

    public IUser? PrimaryUser => _primaryUser;

    public bool IsPrivate => _keyPacket is ISecretKeyPacket;

    public SymmetricAlgorithm[] PreferredSymmetrics { get; }

    public bool AeadSupported { get; }

    public IPacketList PacketList => _packetList;

    public AeadAlgorithm[] PreferredAeads(SymmetricAlgorithm symmetric)
    {
        throw new NotImplementedException();
    }

    public bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    )
    {
        var keyPacket = verifyKey?.KeyPacket ?? _keyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in _revocationSignatures)
        {
            if (keyId == null || Arrays.AreEqual(keyId, signature.IssuerKeyId))
            {
                if (signature.Verify(
                    keyPacket, keyPacket.SignBytes(), time
                ))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public bool IsCertified(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    )
    {
        return _users.Any(user => user.IsPrimary && user.IsCertified(verifyKey, certificate, time));
    }

    public bool Verify(string userId = "", DateTime? time = null)
    {
        if (_directSignatures.Any(
            signature => signature.Verify(_keyPacket, _keyPacket.SignBytes(), time)
        ))
        {
            return true;
        }

        return _users.Where(user => userId.Length == 0 || userId == user.UserId).Any(user => user.Verify(time));
    }

    public abstract IKey CertifyBy(IPrivateKey signKey, DateTime? time = null);

    public abstract IKey RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    );

    public static DateTime? KeyExpiration(ISignaturePacket[] signatures)
    {
        foreach (var signature in signatures)
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
