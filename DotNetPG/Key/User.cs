// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
/// OpenPGP user class.
/// </summary>
public class User : IUser
{
    public User(
        IKey mainKey,
        IUserIdPacket userIdPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] selfSignatures,
        ISignaturePacket[] otherSignatures
    )
    {
        MainKey = mainKey;
        UserIdPacket = userIdPacket;

        RevocationSignatures = revocationSignatures.Where(signature => signature.IsCertRevocation).ToArray();
        Array.Sort(RevocationSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

        SelfSignatures = selfSignatures.Where(signature => signature.IsCertification).ToArray();
        Array.Sort(SelfSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

        OtherSignatures = otherSignatures.Where(signature => signature.IsCertification).ToArray();
        Array.Sort(OtherSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

        PacketList = new PacketList([
            UserIdPacket,
            ..RevocationSignatures,
            ..SelfSignatures,
            ..OtherSignatures
        ]);
    }

    public IKey MainKey { get; }

    public IUserIdPacket UserIdPacket { get; }

    public ISignaturePacket[] RevocationSignatures { get; }

    public ISignaturePacket[] SelfSignatures { get; }

    public ISignaturePacket[] OtherSignatures { get; }

    public bool IsPrimary => SelfSignatures.Any(signature => signature.IsPrimaryUserId);

    public byte[] UserId => UserIdPacket.ToBytes();

    public IPacketList PacketList { get; }

    public bool IsRevoked(
        IKey? verifyKey = null,
        ISignaturePacket? certificate = null,
        DateTime? time = null
    )
    {
        var keyPacket = verifyKey?.KeyPacket ?? MainKey.KeyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in RevocationSignatures)
        {
            if (keyId == null || Arrays.AreEqual(keyId, signature.IssuerKeyId))
            {
                if (signature.Verify(
                    keyPacket,
                    [..MainKey.KeyPacket.SignBytes(), ..UserIdPacket.SignBytes()],
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
        var keyPacket = verifyKey?.KeyPacket ?? MainKey.KeyPacket;
        var keyId = certificate?.IssuerKeyId;
        foreach (var signature in OtherSignatures)
        {
            if (keyId == null || Arrays.AreEqual(keyId, signature.IssuerKeyId))
            {
                if (signature.Verify(
                    keyPacket,
                    [..MainKey.KeyPacket.SignBytes(), ..UserIdPacket.SignBytes()],
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
        foreach (var signature in SelfSignatures)
        {
            if (signature.Verify(
                MainKey.KeyPacket,
                [..MainKey.KeyPacket.SignBytes(), ..UserIdPacket.SignBytes()],
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
        if (Arrays.AreEqual(signKey.Fingerprint, MainKey.Fingerprint))
        {
            throw new Exception("The user\\'s own key can only be used for self-certifications.");
        }
        return new User(
            MainKey,
            UserIdPacket,
            RevocationSignatures,
            SelfSignatures,
            [
                SignaturePacket.CreateCertGeneric(
                    signKey.SecretKeyPacket,
                    MainKey.KeyPacket,
                    UserIdPacket,
                    time
                ),
                ..OtherSignatures,
            ]
        );
    }

    public IUser RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        return new User(
            MainKey,
            UserIdPacket,
            [
                SignaturePacket.CreateCertRevocation(
                    signKey.SecretKeyPacket,
                    MainKey.KeyPacket,
                    UserIdPacket,
                    revocationReason,
                    reasonTag,
                    time
                ),
                ..RevocationSignatures
            ],
            SelfSignatures,
            OtherSignatures
        );
    }
}
