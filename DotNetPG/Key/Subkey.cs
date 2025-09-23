// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using Org.BouncyCastle.Utilities;

namespace DotNetPG.Key;

using Enum;
using Type;

/// <summary>
/// OpenPGP sub key class.
/// </summary>
public class Subkey : ISubkey
{
    private readonly IKey _mainKey;

    private readonly ISubkeyPacket _keyPacket;

    private readonly ISignaturePacket[] _revocationSignatures;

    private readonly ISignaturePacket[] _bindingSignatures;

    public Subkey(
        IKey mainKey,
        ISubkeyPacket keyPacket,
        ISignaturePacket[] revocationSignatures,
        ISignaturePacket[] bindingSignatures
    )
    {
        _mainKey = mainKey;
        _keyPacket = keyPacket;
        _revocationSignatures = revocationSignatures.Where(signature => signature.IsSubkeyRevocation).ToArray();
        _bindingSignatures = bindingSignatures.Where(signature => signature.IsSubkeyBinding).ToArray();
    }

    public IKey  MainKey => _mainKey;

    public ISubkeyPacket KeyPacket => _keyPacket;

    public ISignaturePacket[] RevocationSignatures => _revocationSignatures;

    public ISignaturePacket[] BindingSignatures => _bindingSignatures;

    public int Version => _keyPacket.Version;

    public DateTime? ExpirationTime => BaseKey.KeyExpiration(_bindingSignatures);

    public DateTime? CreationTime => _keyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => _keyPacket.KeyAlgorithm;

    public byte[] Fingerprint => _keyPacket.Fingerprint;

    public byte[] KeyId => _keyPacket.KeyId;

    public int KeyLength => _keyPacket.KeyLength;

    public bool IsSigningKey => _keyPacket.IsSigningKey;

    public bool IsEncryptionKey => _keyPacket.IsEncryptionKey;

    public IPacketList PacketList => new Packet.PacketList([
        _keyPacket,
        .._revocationSignatures,
        .._bindingSignatures
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
                    [.._mainKey.KeyPacket.SignBytes(), ..keyPacket.SignBytes()],
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
        foreach (var signature in _bindingSignatures)
        {
            if (signature.Verify(
                _mainKey.KeyPacket,
                [.._mainKey.KeyPacket.SignBytes(), .._keyPacket.SignBytes()],
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
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason,
        DateTime? time = null
    )
    {
        throw new NotImplementedException();
    }
}
