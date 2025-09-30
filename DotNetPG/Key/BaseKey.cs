// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
using Packet.SubPacket;
using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Abstract OpenPGP key class
/// </summary>
public abstract class BaseKey : IKey
{
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
        KeyPacket = keyPackets.OfType<IKeyPacket>().First();

        var remainPackets = packetList.Packets.SkipWhile(packet => packet is IKeyPacket).ToList();
        RevocationSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();
        Array.Sort(RevocationSignatures, (a, b) =>
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
        DirectSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsDirectKey;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();
        Array.Sort(DirectSignatures, (a, b) =>
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
                    if (Arrays.AreEqual(signature.IssuerKeyId, KeyPacket.KeyId))
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
        Users = users.ToArray();
        Array.Sort(Users, (a, b) =>
        {
            var aTime = a.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            var bTime = b.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        PrimaryUser = users.Find(user => user.IsPrimary);

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
        Subkeys = subkeys.ToArray();
        Array.Sort(Subkeys, (a, b) => (int)(new DateTimeOffset(a.CreationTime).ToUnixTimeSeconds() - new DateTimeOffset(b.CreationTime).ToUnixTimeSeconds()));

        IList<IPacket> packets = [
            KeyPacket,
            ..RevocationSignatures,
            ..DirectSignatures,
            ..Users.SelectMany(user => user.PacketList.Packets),
            ..Subkeys.SelectMany(subkey => subkey.PacketList.Packets),
        ];
        if (Version == (int) KeyVersion.V6)
        {
            packets.Add(Padding.CreatePadding());
        }
        PacketList = new PacketList(packets.ToArray());
    }

    protected BaseKey(
        IKeyPacket keyPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] directSignatures,
        IUser[] users,
        ISubkey[] subkeys
    )
    {
        KeyPacket = keyPacket;
        RevocationSignatures = revocationSignatures;
        DirectSignatures = directSignatures;
        Users = users;
        Subkeys = subkeys;
        PrimaryUser = users.ToList().Find(user => user.IsPrimary);

        IList<IPacket> packets = [
            KeyPacket,
            ..RevocationSignatures,
            ..DirectSignatures,
            ..Users.SelectMany(user => user.PacketList.Packets),
            ..Subkeys.SelectMany(subkey => subkey.PacketList.Packets),
        ];
        if (Version == (int) KeyVersion.V6)
        {
            packets.Add(Padding.CreatePadding());
        }
        PacketList = new PacketList(packets.ToArray());
    }

    public IKeyPacket KeyPacket { get; }

    public int Version => KeyPacket.Version;

    public DateTime? ExpirationTime => KeyExpiration(DirectSignatures);

    public DateTime CreationTime => KeyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => KeyPacket.KeyAlgorithm;

    public byte[] Fingerprint => KeyPacket.Fingerprint;

    public byte[] KeyId => KeyPacket.KeyId;

    public int KeyLength => KeyPacket.KeyLength;

    public ISignaturePacket[] RevocationSignatures { get; }

    public ISignaturePacket[] DirectSignatures { get; }

    public IUser[] Users { get; }

    public ISubkey[] Subkeys { get; }

    public IUser? PrimaryUser { get; }

    public bool IsPrivate => KeyPacket is ISecretKeyPacket;

    public SymmetricAlgorithm[] PreferredSymmetrics
    {
        get
        {
            var preferred =
                DirectSignatures.FirstOrDefault()?.GetSubPacket<PreferredSymmetricAlgorithms>()?.Preferences ??
                PrimaryUser?.SelfSignatures.FirstOrDefault()?.GetSubPacket<PreferredSymmetricAlgorithms>()?.Preferences;
            return preferred ?? [];
        }
    }

    public bool AeadSupported
    {
        get
        {
            var support = DirectSignatures.FirstOrDefault()?.GetSubPacket<Features>()?.SupportV2Seipd;
            return support ?? false;
        }
    }

    public IPacketList PacketList { get; }

    public AeadAlgorithm[] PreferredAeads(SymmetricAlgorithm symmetric)
    {
        var preferred = DirectSignatures.FirstOrDefault()?.GetSubPacket<PreferredAeadCiphers>()?.PreferredAeads(symmetric);
        return preferred ?? [];
    }

    public bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    )
    {
        var keyPacket = verifyKey?.KeyPacket ?? KeyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in RevocationSignatures)
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
        return Users.Any(user => user.IsPrimary && user.IsCertified(verifyKey, certificate, time));
    }

    public bool Verify(string userId = "", DateTime? time = null)
    {
        if (DirectSignatures.Any(
            signature => signature.Verify(KeyPacket, KeyPacket.SignBytes(), time)
        ))
        {
            return true;
        }

        return Users.Where(user => userId.Length == 0 || userId == user.UserId).Any(user => user.Verify(time));
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
