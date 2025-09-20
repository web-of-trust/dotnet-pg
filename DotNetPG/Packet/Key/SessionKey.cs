// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Security;

/// <summary>
///     Session key class
/// </summary>
public class SessionKey(
    byte[] encryptionKey,
    SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
    AeadAlgorithm? aead = null)
    : ISessionKey
{
    public byte[] EncryptionKey => encryptionKey;

    public SymmetricAlgorithm Symmetric => symmetric;

    public AeadAlgorithm? Aead => aead;

    public ISessionKey Checksum(byte[] checksum)
    {
        var computed = ComputeChecksum();
        if (!(computed[0] == checksum[0] && computed[1] == checksum[1]))
            throw new Exception("Session key checksum mismatch!");

        return this;
    }

    public byte[] ComputeChecksum()
    {
        var sum = encryptionKey.Aggregate(0, (current, t) => current + t);
        return Helper.Pack16((short)(sum & 0xffff));
    }

    public byte[] ToBytes()
    {
        return [(byte)symmetric, ..encryptionKey];
    }

    /// <summary>
    ///     Read session key from bytes
    /// </summary>
    public static ISessionKey FromBytes(byte[] bytes)
    {
        var sessionKey = new SessionKey(
            bytes.Skip(1).Take(bytes.Length - 3).ToArray(), (SymmetricAlgorithm)bytes[0]
        );
        return sessionKey.Checksum(bytes.Skip(bytes.Length - 2).ToArray());
    }

    /// <summary>
    ///     Produce session key specify by symmetric algorithm
    /// </summary>
    public static ISessionKey ProduceKey(
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256,
        AeadAlgorithm? aead = null
    )
    {
        return new SessionKey(
            SecureRandom.GetNextBytes(
                new SecureRandom(),
                (Helper.SymmetricKeySize(symmetric) + 7) >> 3
            ),
            symmetric,
            aead
        );
    }
}