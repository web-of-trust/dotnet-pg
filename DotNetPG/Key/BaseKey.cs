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
        var revocations = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();
        RevocationSignatures = SortSignatures(revocations).AsReadOnly();

        remainPackets = remainPackets.SkipWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsKeyRevocation;
            }
            return false;
        }).ToList();
        var directSignatures = remainPackets.TakeWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsDirectKey;
            }
            return false;
        }).OfType<ISignaturePacket>().ToArray();
        DirectSignatures = SortSignatures(directSignatures).AsReadOnly();

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
        var userArray = users.ToArray();
        Array.Sort(userArray, (a, b) =>
        {
            var aTime = a.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            var bTime = b.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        Users = userArray.AsReadOnly();
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
        var subkeyArray = subkeys.ToArray();
        Array.Sort(subkeyArray, (a, b) => (int)(new DateTimeOffset(a.CreationTime).ToUnixTimeSeconds() - new DateTimeOffset(b.CreationTime).ToUnixTimeSeconds()));
        Subkeys = subkeyArray.AsReadOnly();

        IList<IPacket> packets = [
            KeyPacket,
            ..RevocationSignatures,
            ..DirectSignatures,
            ..Users.SelectMany(user => user.PacketList.Packets),
            ..Subkeys.SelectMany(subkey => subkey.PacketList.Packets),
        ];
        if (KeyPacket.IsV6Key)
        {
            packets.Add(Padding.CreatePadding());
        }
        PacketList = new PacketList(packets);
    }

    protected BaseKey(
        IKeyPacket keyPacket,
        IList<ISignaturePacket> revocationSignatures,
        IList<ISignaturePacket> directSignatures,
        IList<IUser> users,
        IList<ISubkey> subkeys
    )
    {
        KeyPacket = keyPacket;

        var revocations = revocationSignatures.Where(signature => signature.IsKeyRevocation).ToArray();
        RevocationSignatures = SortSignatures(revocations).AsReadOnly();

        var directs = directSignatures.Where(signature => signature.IsDirectKey).ToArray();
        DirectSignatures = SortSignatures(directs).AsReadOnly();

        var userArray = users.ToArray();
        Array.Sort(userArray, (a, b) =>
        {
            var aTime = a.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            var bTime = b.SelfSignatures.FirstOrDefault()?.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        Users = userArray.AsReadOnly();
        PrimaryUser = users.ToList().Find(user => user.IsPrimary);

        var subkeyArray = subkeys.ToArray();
        Array.Sort(subkeyArray, (a, b) => (int)(new DateTimeOffset(a.CreationTime).ToUnixTimeSeconds() - new DateTimeOffset(b.CreationTime).ToUnixTimeSeconds()));
        Subkeys = subkeyArray.AsReadOnly();

        IList<IPacket> packets = [
            KeyPacket,
            ..RevocationSignatures,
            ..DirectSignatures,
            ..Users.SelectMany(user => user.PacketList.Packets),
            ..Subkeys.SelectMany(subkey => subkey.PacketList.Packets),
        ];
        if (keyPacket.IsV6Key)
        {
            packets.Add(Padding.CreatePadding());
        }
        PacketList = new PacketList(packets);
    }

    public IKeyPacket KeyPacket { get; }

    public int Version => KeyPacket.Version;

    public DateTime? ExpirationTime => KeyExpiration(DirectSignatures);

    public DateTime CreationTime => KeyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => KeyPacket.KeyAlgorithm;

    public byte[] Fingerprint => KeyPacket.Fingerprint;

    public byte[] KeyId => KeyPacket.KeyId;

    public int KeyLength => KeyPacket.KeyLength;

    public IList<ISignaturePacket> RevocationSignatures { get; }

    public IList<ISignaturePacket> DirectSignatures { get; }

    public IList<IUser> Users { get; }

    public IList<ISubkey> Subkeys { get; }

    public IUser? PrimaryUser { get; }

    public bool IsPrivate => KeyPacket is ISecretKeyPacket;

    public IList<SymmetricAlgorithm> PreferredSymmetrics
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

    public IList<AeadAlgorithm> PreferredAeads(SymmetricAlgorithm symmetric)
    {
        var preferred = DirectSignatures.FirstOrDefault()?.GetSubPacket<PreferredAeadCiphers>()?.PreferredAeads(symmetric);
        return preferred ?? [];
    }

    public IKeyPacket GetSigningKeyPacket(byte[]? keyId = null, DateTime? time = null)
    {
        foreach (var subkey in Subkeys)
        {
            if (Arrays.IsNullOrEmpty(keyId) || Arrays.AreEqual(keyId, subkey.KeyId))
            {
                if (!subkey.IsSigningKey || subkey.IsRevoked(time: time))
                {
                    continue;
                }

                var signature = subkey.BindingSignatures[0].GetSubPacket<EmbeddedSignature>();
                if (signature != null)
                {
                    if (signature.Signature.Verify(
                        subkey.KeyPacket, [..KeyPacket.SignBytes(), ..subkey.KeyPacket.SignBytes()], time
                    ))
                    {
                        return subkey.KeyPacket;
                    }
                }
                else
                {
                    throw new Exception("Missing embedded signature.");
                }
            }
        }

        if (!KeyPacket.IsSigningKey || (!Arrays.IsNullOrEmpty(keyId) && !Arrays.AreEqual(keyId, KeyId)))
        {
            throw new Exception("Could not find valid signing key packet.");
        }
        return KeyPacket;
    }

    public IKeyPacket GetEncryptionKeyPacket(byte[]? keyId = null, DateTime? time = null)
    {
        foreach (var subkey in Subkeys)
        {
            if (Arrays.IsNullOrEmpty(keyId) || Arrays.AreEqual(keyId, subkey.KeyId))
            {
                if (!subkey.IsEncryptionKey || subkey.IsRevoked(time: time))
                {
                    continue;
                }
                return subkey.KeyPacket;
            }
        }

        if (!KeyPacket.IsEncryptionKey || (!Arrays.IsNullOrEmpty(keyId) && !Arrays.AreEqual(keyId, KeyId)))
        {
            throw new Exception("Could not find valid encryption key packet.");
        }

        return KeyPacket;
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

    public static DateTime? KeyExpiration(IList<ISignaturePacket> signatures)
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

    public static ISignaturePacket[] SortSignatures(ISignaturePacket[] signatures)
    {
        Array.Sort(signatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });
        return signatures;
    }
}
