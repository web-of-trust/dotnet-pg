// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using DotNetPG.Type;

namespace DotNetPG.Key;

/// <summary>
///     Abstract OpenPGP key class
/// </summary>
public abstract class BaseKey
{
    private readonly IKeyPacket _keyPacket;

    private readonly IList<ISignaturePacket> _revocationSignatures;

    private readonly IList<ISignaturePacket> _directSignatures;

    private readonly IList<IUser> _users;

    private readonly IList<ISubkey> _subkey;

    public BaseKey(IPacketList packetList)
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
        }).OfType<ISignaturePacket>().ToList();

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
        }).OfType<ISignaturePacket>().ToList();

        remainPackets = remainPackets.SkipWhile(packet =>
        {
            if (packet is ISignaturePacket signature)
            {
                return signature.IsDirectKey;
            }
            return false;
        }).ToList();
    }

    public IKeyPacket  KeyPacket => _keyPacket;

    public IReadOnlyList<ISignaturePacket> RevocationSignatures => _revocationSignatures.AsReadOnly();

    public IReadOnlyList<ISignaturePacket> DirectSignatures => _directSignatures.AsReadOnly();

    public IReadOnlyList<IUser> Users => _users.AsReadOnly();

    public IReadOnlyList<ISubkey> Subkey => _subkey.AsReadOnly();
    
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
            else if (signature.ExpirationTime != null)
            {
                return signature.ExpirationTime;
            }
        }
        return null;
    }
}
