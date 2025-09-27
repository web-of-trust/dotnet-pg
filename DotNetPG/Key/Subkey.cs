// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Enum;
using Packet;
using Type;
using Org.BouncyCastle.Utilities;

/// <summary>
/// OpenPGP sub key class.
/// </summary>
public class Subkey : ISubkey
{
    public Subkey(
        IKey mainKey,
        ISubkeyPacket keyPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] bindingSignatures
    )
    {
        MainKey = mainKey;
        KeyPacket = keyPacket;

        RevocationSignatures = revocationSignatures.Where(signature => signature.IsSubkeyRevocation).ToArray();
        Array.Sort(RevocationSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

        BindingSignatures = bindingSignatures.Where(signature => signature.IsSubkeyBinding).ToArray();
        Array.Sort(BindingSignatures, (a, b) =>
        {
            var aTime = a.CreationTime ?? DateTime.Now;
            var bTime = b.CreationTime ?? DateTime.Now;
            return (int)(new DateTimeOffset(aTime).ToUnixTimeSeconds() - new DateTimeOffset(bTime).ToUnixTimeSeconds());
        });

        PacketList = new PacketList([
            KeyPacket,
            ..RevocationSignatures,
            ..BindingSignatures
        ]);
    }

    public IKey MainKey { get; }

    public ISubkeyPacket KeyPacket { get; }

    public ISignaturePacket[] RevocationSignatures { get; }

    public ISignaturePacket[] BindingSignatures { get; }

    public int Version => KeyPacket.Version;

    public DateTime? ExpirationTime => BaseKey.KeyExpiration(BindingSignatures);

    public DateTime CreationTime => KeyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => KeyPacket.KeyAlgorithm;

    public byte[] Fingerprint => KeyPacket.Fingerprint;

    public byte[] KeyId => KeyPacket.KeyId;

    public int KeyLength => KeyPacket.KeyLength;

    public bool IsSigningKey => KeyPacket.IsSigningKey;

    public bool IsEncryptionKey => KeyPacket.IsEncryptionKey;

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
                    [..MainKey.KeyPacket.SignBytes(), ..keyPacket.SignBytes()],
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
        foreach (var signature in BindingSignatures)
        {
            if (signature.Verify(
                MainKey.KeyPacket,
                [..MainKey.KeyPacket.SignBytes(), ..KeyPacket.SignBytes()],
                time
            ))
            {
                return true;
            }
        }
        return false;
    }

    public ISubkey RevokeBy(
        IPrivateKey signKey,
        string revocationReason = "",
        RevocationReasonTag reasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        return new Subkey(
            MainKey,
            KeyPacket,
            [
                SignaturePacket.CreateSubkeyRevocation(
                    signKey.SecretKeyPacket,
                    MainKey.KeyPacket,
                    KeyPacket,
                    revocationReason,
                    reasonTag,
                    time
                ),
                ..RevocationSignatures
            ],
            BindingSignatures
        );
    }
}
