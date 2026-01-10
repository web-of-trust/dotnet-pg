// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Common;
using Enum;
using Packet.Key;
using Type;

/// <summary>
/// Session key generator
/// </summary>
public class SessionKeyGenerator : ISessionKeyGenerator
{
    private IList<IKey> _encryptionKeys = [];
    private SymmetricAlgorithm _defaultSymmetric = Config.PreferredSymmetric;

    public SessionKeyGenerator WithEncryptionKeys(IList<IKey> encryptionKeys)
    {
        _encryptionKeys = encryptionKeys;
        return this;
    }

    public SessionKeyGenerator WithDefaultSymmetric(SymmetricAlgorithm symmetric)
    {
        _defaultSymmetric = symmetric;
        return this;
    }

    public ISessionKey Generate()
    {
        IList<SymmetricAlgorithm> preferredSymmetrics = [];
        foreach (var key in _encryptionKeys)
        {
            if (preferredSymmetrics.Count == 0)
            {
                preferredSymmetrics = key.PreferredSymmetrics;
            }
            else
            {
                preferredSymmetrics = preferredSymmetrics.TakeWhile(
                    prefer => key.PreferredSymmetrics.Contains(prefer)
                ).ToList();
            }
        }
        var symmetric = preferredSymmetrics.Count > 0 ?
            preferredSymmetrics[0] : _defaultSymmetric;

        IList<AeadAlgorithm> preferredAeads = [
            AeadAlgorithm.Ocb,
            AeadAlgorithm.Gcm,
            AeadAlgorithm.Eax
        ];
        var aeadProtect = Config.AeadProtect;
        foreach (var key in _encryptionKeys)
        {
            if (key.AeadSupported)
            {
                preferredAeads = preferredAeads.TakeWhile(
                    prefer => key.PreferredAeads(symmetric).Contains(prefer)
                ).ToList();
                aeadProtect = true;
            }
            else
            {
                aeadProtect = false;
                break;
            }
        }
        var aead = preferredAeads.Count > 0 ? preferredAeads[0] : Config.PreferredAead;

        return SessionKey.ProduceKey(symmetric, aeadProtect ? aead : null);
    }
}
