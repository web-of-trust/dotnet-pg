// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using Org.BouncyCastle.Utilities;

namespace DotNetPG.Key;

using Enum;
using Type;

/// <summary>
/// OpenPGP user class.
/// </summary>
public class User : IUser
{
    private readonly IKey _mainKey;

    private readonly IUserIdPacket _userIdPacket;

    private readonly ISignaturePacket[] _revocationSignatures;

    private readonly ISignaturePacket[] _selfSignatures;

    private readonly ISignaturePacket[] _otherSignatures;

    public User(
        IKey mainKey,
        IUserIdPacket userIdPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] selfSignatures,
        ISignaturePacket[] otherSignatures
    )
    {
        _mainKey = mainKey;
        _userIdPacket = userIdPacket;
        _revocationSignatures = revocationSignatures.Where(signature => signature.IsCertRevocation).ToArray();
        _selfSignatures = selfSignatures.Where(signature => signature.IsCertification).ToArray();
        _otherSignatures = otherSignatures.Where(signature => signature.IsCertification).ToArray();
    }

    public IKey MainKey => _mainKey;

    public IUserIdPacket UserIdPacket => _userIdPacket;

    public ISignaturePacket[] RevocationSignatures => _revocationSignatures;

    public ISignaturePacket[] SelfSignatures => _selfSignatures;

    public ISignaturePacket[] OtherSignatures => _otherSignatures;

    public bool IsPrimary
    {
        get
        {
            var signatures = _selfSignatures.ToList();
            signatures.Sort((a, b) =>
            {
                var aTime = a.CreationTime ?? DateTime.Now;
                var bTime = b.CreationTime ?? DateTime.Now;
                return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
            });
            return signatures.Any(signature => signature.IsPrimaryUserId);
        }
    }

    public byte[] UserId => _userIdPacket.ToBytes();

    public IPacketList PacketList => new Packet.PacketList([
        _userIdPacket,
        .._revocationSignatures,
        .._selfSignatures,
        .._otherSignatures
    ]);

    public bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    )
    {
        var keyPacket = verifyKey?.KeyPacket ?? _mainKey.KeyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in _revocationSignatures)
        {
            if (keyId == null || Arrays.AreEqual(keyId, signature.IssuerKeyId))
            {
                if (signature.Verify(
                    keyPacket,
                    [.._mainKey.KeyPacket.SignBytes(), .._userIdPacket.SignBytes()],
                    time
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
        var keyPacket = verifyKey?.KeyPacket ?? _mainKey.KeyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in _otherSignatures)
        {
            if (keyId == null || Arrays.AreEqual(keyId, signature.IssuerKeyId))
            {
                if (signature.Verify(
                        keyPacket,
                        [.._mainKey.KeyPacket.SignBytes(), .._userIdPacket.SignBytes()],
                        time
                    ))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public bool Verify(DateTime? time = null)
    {
        foreach (var signature in _selfSignatures)
        {
            if (signature.Verify(
                _mainKey.KeyPacket,
                [.._mainKey.KeyPacket.SignBytes(), .._userIdPacket.SignBytes()],
                time
            ))
            {
                return true;
            }
        }
        return false;
    }

    public IUser CertifyBy(IPrivateKey signKey, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IUser RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        throw new NotImplementedException();
    }
}
