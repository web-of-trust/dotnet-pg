// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Key;

using Common;
using Enum;
using Packet;
using Type;

/// <summary>
/// OpenPGP key pair generator
/// </summary>
public class KeyGenerator : IKeyGenerator
{
    private IList<string> _userIds = [];
    private string _passphrase = "";
    private KeyType _keyType = KeyType.Rsa;
    private RsaKeySize _keySize = RsaKeySize.Normal;
    private EcCurve _curve = EcCurve.Secp521R1;
    private int _keyExpiry;
    private bool _signOnly;

    public KeyGenerator WithUserIds(IList<string> userIds)
    {
        _userIds = userIds;
        return this;
    }

    public KeyGenerator WithPassphrase(string passphrase)
    {
        _passphrase = passphrase;
        return this;
    }

    public KeyGenerator WithKeyType(KeyType keyType)
    {
        _keyType = keyType;
        return this;
    }

    public KeyGenerator WithRsaKeySize(RsaKeySize keySize)
    {
        _keySize = keySize;
        return this;
    }

    public KeyGenerator WithEcCurve(EcCurve curve)
    {
        _curve = curve;
        return this;
    }

    public KeyGenerator WithKeyExpiry(int keyExpiry)
    {
        _keyExpiry = keyExpiry;
        return this;
    }

    public KeyGenerator WithSignOnly(bool signOnly)
    {
        _signOnly = signOnly;
        return this;
    }

    public IPrivateKey Generate(DateTime? time = null)
    {
        if (_userIds.Count == 0 || _passphrase.Length == 0)
        {
            throw new ArgumentException(
                "UserIDs and passphrase are required for key generation."
            );
        }

        var keyAlgorithm = _keyType switch
        {
            KeyType.Ecc => _curve == EcCurve.Ed25519 ?
                KeyAlgorithm.EdDsaLegacy : KeyAlgorithm.EcDsa,
            KeyType.Curve25519 => KeyAlgorithm.Ed25519,
            KeyType.Curve448 => KeyAlgorithm.Ed448,
            _ => KeyAlgorithm.RsaGeneral
        };

        var secretKey = SecretKey.Generate(keyAlgorithm, _keySize, _curve, time);
        AeadAlgorithm? aead = secretKey.IsV6Key && Config.AeadProtect ?
            Config.PreferredAead : null;

        IList<IPacket> packets = [
            secretKey.Encrypt(_passphrase, Config.PreferredSymmetric, aead)
        ];
        if (secretKey.IsV6Key)
        {
            // Wrap secret key with direct key signature
            packets.Add(
                SignaturePacket.CreateDirectKeySignature(
                    secretKey, _keyExpiry, time
                )
            );
        }

        // Wrap user id with certificate signature
        var index = 0;
        foreach (var userId in _userIds)
        {
            var userPacket = new UserId(userId);
            packets.Add(userPacket);
            packets.Add(SignaturePacket.CreateSelfCertificate(
                secretKey,
                userPacket,
                index == 0,
                _keyExpiry,
                time
            ));
            index++;
        }

        if (!_signOnly)
        {
            // Generate & Wrap secret subkey with binding signature
            var subkeyAlgorithm = _keyType switch
            {
                KeyType.Ecc => KeyAlgorithm.EcDh,
                KeyType.Curve25519 => KeyAlgorithm.X25519,
                KeyType.Curve448 => KeyAlgorithm.X448,
                _ => KeyAlgorithm.RsaGeneral
            };
            var subkeyCurve = keyAlgorithm == KeyAlgorithm.EdDsaLegacy ?
                EcCurve.Curve25519 : _curve;
            var secretSubkey = SecretSubkey.Generate(
                subkeyAlgorithm, _keySize, subkeyCurve, time
            );
            packets.Add(
                secretSubkey.Encrypt(
                    _passphrase,
                    Config.PreferredSymmetric,
                    aead
                )
            );
            packets.Add(SignaturePacket.CreateSubkeyBinding(
                secretKey,
                secretSubkey,
                _keyExpiry,
                false,
                time
            ));
        }
        return new PrivateKey(new PacketList(packets));
    }
}
